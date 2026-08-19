use crate::analysis::{value_recovery::ValueRecovery, SemanticTransform};
use crate::ir::semantic::SemanticDeadCodeElimination;
use crate::ir::{
    analysis::{SourceVariableAllocation, TypeHierarchy, TypeSolver},
    cfg::CFG,
    passes::CfgPipeline,
    structure::RegionReducer,
    ArgType, ExceptionAnalyzer, MemberReference, RegionGraphBuilder, SemanticMethod, SemanticNode,
    SemanticVisitor, SourceSyntaxSemantics, StringBuildingRecovery,
};
use crate::language::java::{JavaValueSyntax, SourceSyntaxRecovery};

use super::JavaDecompilerError;

pub(super) struct MethodBodyAnalysis {
    pub semantic: SemanticMethod<SourceSyntaxSemantics>,
    pub is_static: bool,
    pub this_code_var: Option<u32>,
    pub parameter_code_vars: Vec<Option<u32>>,
    pub type_uses: std::collections::BTreeSet<ArgType>,
}

pub(super) struct MethodBodyPipeline<'a> {
    hierarchy: &'a dyn TypeHierarchy,
    observer: &'a dyn crate::ir::AnalysisObserver,
}

impl<'a> MethodBodyPipeline<'a> {
    pub(super) fn new(
        hierarchy: &'a dyn TypeHierarchy,
        observer: &'a dyn crate::ir::AnalysisObserver,
    ) -> Self {
        Self {
            hierarchy,
            observer,
        }
    }

    pub(super) fn analyze(&self, cfg: &mut CFG) -> Result<MethodBodyAnalysis, JavaDecompilerError> {
        crate::profile_scope!("method_pipeline.total", self.analyze_impl(cfg))
    }

    fn analyze_impl(&self, cfg: &mut CFG) -> Result<MethodBodyAnalysis, JavaDecompilerError> {
        let stats = method_stats_enabled();
        let mut stages: Vec<(&str, u128)> = Vec::new();
        let mark =
            |stages: &mut Vec<(&str, u128)>, name: &'static str, start: std::time::Instant| {
                if stats {
                    stages.push((name, start.elapsed().as_micros()));
                }
            };

        self.observer.checkpoint()?;
        let cfg_pipeline = CfgPipeline::new(self.hierarchy);
        let t = std::time::Instant::now();
        let cfg_analysis = crate::profile_scope!("method_pipeline.cfg_ssa", {
            cfg_pipeline.analyze_observed(cfg, self.observer)
        })?;
        mark(&mut stages, "cfg_ssa", t);
        self.observe_stage(cfg, "cfg_ssa:done")?;
        let ssa_values = cfg_analysis.values;

        let t = std::time::Instant::now();
        let exception_analysis = crate::profile_scope!("method_pipeline.exception_analysis", {
            ExceptionAnalyzer::new(cfg, &ssa_values, self.hierarchy).analyze()
        })?;
        mark(&mut stages, "exceptions", t);
        self.observe_stage(cfg, "exceptions:done")?;
        self.observer.observe(crate::ir::AnalysisEvent::Exceptions {
            cfg,
            analysis: &exception_analysis,
        });
        self.observer
            .observe(crate::ir::AnalysisEvent::ControlFlow(cfg));

        let t = std::time::Instant::now();
        let region_graph =
            RegionGraphBuilder::new(cfg, &exception_analysis, &ssa_values).build()?;
        mark(&mut stages, "regions", t);
        self.observe_stage(cfg, "regions:done")?;
        self.observer.observe(crate::ir::AnalysisEvent::Regions {
            cfg,
            graph: &region_graph,
        });
        let t = std::time::Instant::now();
        let body = crate::profile_scope!("method_pipeline.structure", {
            RegionReducer::new(cfg, &region_graph, self.observer)
                .and_then(|reducer| reducer.reduce())
                .map_err(JavaDecompilerError::from)
        })?;
        mark(&mut stages, "structure", t);
        self.observe_stage(cfg, "structure:done")?;
        self.observe_semantics(cfg, crate::ir::SemanticStage::Structured, &body);
        let semantic = SemanticMethod::from_ssa(body, region_graph, ssa_values);
        let t = std::time::Instant::now();
        semantic.verify()?;
        mark(&mut stages, "verify1", t);
        let mut value_recovery = ValueRecovery::new(cfg)?;
        let t = std::time::Instant::now();
        let semantic = crate::profile_scope!("method_pipeline.value_recovery", {
            value_recovery.transform(semantic)
        })?;
        mark(&mut stages, "value_recovery", t);
        self.observer
            .observe(crate::ir::AnalysisEvent::ValueRecovery {
                cfg,
                diagnostics: value_recovery.diagnostics(),
            });
        self.observe_stage(cfg, "values:done")?;
        let t = std::time::Instant::now();
        semantic.verify()?;
        mark(&mut stages, "verify2", t);
        self.observe_semantics(
            cfg,
            crate::ir::SemanticStage::ValuesRecovered,
            semantic.body(),
        );
        let t = std::time::Instant::now();
        let types = crate::profile_scope!("method_pipeline.type_recovery", {
            TypeSolver::new(self.hierarchy).solve(
                cfg,
                semantic.state().values(),
                semantic.state().constants(),
            )
        })?;
        mark(&mut stages, "types", t);
        self.observe_stage(cfg, "types:done")?;
        let t = std::time::Instant::now();
        let source_variables = SourceVariableAllocation::analyze(
            cfg,
            semantic.state().values(),
            semantic.state().constants(),
            semantic.state().recovered_phis(),
            semantic.body(),
            &types,
            self.hierarchy,
            semantic.state().regions(),
        )?;
        mark(&mut stages, "source_analysis", t);
        self.observe_stage(cfg, "source_analysis:done")?;
        let t = std::time::Instant::now();
        let mut semantic = crate::profile_scope!("method_pipeline.source_variables", {
            source_variables.apply(cfg, semantic, types, self.hierarchy)
        })?;
        mark(&mut stages, "source_apply", t);
        value_recovery.bind_source_inputs(cfg);
        self.observe_stage(cfg, "source_apply:done")?;
        let t = std::time::Instant::now();
        semantic.verify()?;
        mark(&mut stages, "verify3", t);
        self.observe_semantics(
            cfg,
            crate::ir::SemanticStage::SourceAllocated,
            semantic.body(),
        );
        let t = std::time::Instant::now();
        crate::profile_scope!("method_pipeline.source_prepare", {
            value_recovery.prepare_source(&mut semantic)
        })?;
        if cfg.method().descriptor().return_type == ArgType::VOID {
            semantic.normalize_void_method_completion()?;
        }
        mark(&mut stages, "source_prepare", t);
        self.observe_stage(cfg, "source_prepare:done")?;
        let t = std::time::Instant::now();
        semantic.verify()?;
        mark(&mut stages, "verify4", t);
        self.observe_semantics(
            cfg,
            crate::ir::SemanticStage::SourceVariables,
            semantic.body(),
        );
        let t = std::time::Instant::now();
        let mut semantic = crate::profile_scope!("method_pipeline.java_syntax", {
            SourceSyntaxRecovery::new(self.hierarchy).transform(semantic)
        })?;
        mark(&mut stages, "java_syntax", t);
        self.observe_stage(cfg, "java_syntax:done")?;
        let t = std::time::Instant::now();
        semantic.verify()?;
        mark(&mut stages, "verify5", t);
        self.observe_semantics(cfg, crate::ir::SemanticStage::SourceSyntax, semantic.body());
        let t = std::time::Instant::now();
        let fp_iters = crate::profile_scope!("method_pipeline.java_value_fixed_point", {
            JavaValueFixedPoint::new(&mut value_recovery, self.hierarchy).apply(&mut semantic)
        })?;
        mark(&mut stages, "java_fixed_point", t);
        if stats {
            stages.push(("fp_iters", u128::from(fp_iters)));
        }
        self.observe_stage(cfg, "java_values:done")?;
        let t = std::time::Instant::now();
        semantic.verify()?;
        mark(&mut stages, "verify6", t);
        semantic.compact()?;
        self.observe_stage(cfg, "compact:done")?;
        let t = std::time::Instant::now();
        semantic.verify()?;
        mark(&mut stages, "verify7", t);
        self.observe_semantics(cfg, crate::ir::SemanticStage::Normalized, semantic.body());
        if stats {
            let total: u128 = stages
                .iter()
                .filter(|(name, _)| *name != "fp_iters")
                .map(|(_, us)| *us)
                .sum();
            if total >= 5_000 {
                let method = cfg.method();
                eprintln!(
                    "dexdec method {}->{}{} total={:.2}ms fp_iters={} [{}]",
                    method.owner(),
                    method.name(),
                    method.descriptor(),
                    total as f64 / 1000.0,
                    fp_iters,
                    stages
                        .iter()
                        .map(|(name, us)| {
                            if *name == "fp_iters" {
                                format!("{name}={us}")
                            } else {
                                format!("{name}={:.2}", *us as f64 / 1000.0)
                            }
                        })
                        .collect::<Vec<_>>()
                        .join(" "),
                );
            }
        }
        if cfg.method().descriptor().return_type != ArgType::VOID
            && crate::ir::semantic::SemanticCompletion::analyze(semantic.body())
                .can_complete_normally()
        {
            self.observer
                .observe(crate::ir::AnalysisEvent::IncompleteMethod {
                    cfg,
                    stage: crate::ir::SemanticStage::Normalized,
                });
        }
        let type_uses = MethodTypeUses::collect(&semantic)?;
        self.observe_stage(cfg, "type_uses:done")?;

        Ok(MethodBodyAnalysis {
            semantic,
            is_static: cfg.method().is_static(),
            this_code_var: cfg.this_code_variable(),
            parameter_code_vars: cfg.parameter_code_variables().to_vec(),
            type_uses,
        })
    }

    fn observe_semantics(&self, cfg: &CFG, stage: crate::ir::SemanticStage, root: &SemanticNode) {
        self.observer
            .observe(crate::ir::AnalysisEvent::Semantics { cfg, stage, root });
    }

    fn observe_stage(&self, cfg: &CFG, stage: &'static str) -> Result<(), JavaDecompilerError> {
        self.observer
            .observe(crate::ir::AnalysisEvent::MethodPipeline { cfg, stage });
        self.observer.checkpoint()?;
        Ok(())
    }
}

/// Alternates source-identity scheduling and Java expression canonicalization
/// until neither can expose another simplification.
///
/// Every component is monotone: scheduling removes definitions or substitutes
/// their uses, string building merges statements into the one that allocates
/// their builder, and syntax recovery replaces expressions with cheaper
/// equivalents. The fixed point therefore terminates without an iteration cap.
struct JavaValueFixedPoint<'a, 'hierarchy> {
    values: &'a mut ValueRecovery,
    syntax: JavaValueSyntax<'hierarchy>,
}

impl<'a, 'hierarchy> JavaValueFixedPoint<'a, 'hierarchy> {
    fn new(values: &'a mut ValueRecovery, hierarchy: &'hierarchy dyn TypeHierarchy) -> Self {
        Self {
            values,
            syntax: JavaValueSyntax::new(hierarchy),
        }
    }

    fn apply(
        &mut self,
        method: &mut SemanticMethod<SourceSyntaxSemantics>,
    ) -> Result<u32, JavaDecompilerError> {
        let mut iterations = 0u32;
        loop {
            iterations += 1;
            let values_changed = self.values.recover_source(method)?;
            let building_changed = StringBuildingRecovery::apply(method.body_mut())?;
            let syntax_changed = self.syntax.apply(method)?;
            let dead_changed = SemanticDeadCodeElimination::apply(method.body_mut())?;
            if !values_changed && !building_changed && !syntax_changed && !dead_changed {
                return Ok(iterations);
            }
        }
    }
}

fn method_stats_enabled() -> bool {
    std::env::var_os("DEXDEC_METHOD_STATS").is_some()
}

struct MethodTypeUses<'a> {
    types: &'a crate::ir::analysis::SourceTypeEnvironment,
    uses: std::collections::BTreeSet<ArgType>,
    error: Option<crate::ir::analysis::TypeConstraintError>,
}

impl<'a> MethodTypeUses<'a> {
    fn collect(
        method: &'a SemanticMethod<SourceSyntaxSemantics>,
    ) -> Result<std::collections::BTreeSet<ArgType>, JavaDecompilerError> {
        let mut uses = method
            .state()
            .types()
            .known_types()
            .cloned()
            .collect::<std::collections::BTreeSet<_>>();
        uses.extend([
            ArgType::object("java/lang/Float"),
            ArgType::object("java/lang/Double"),
            ArgType::object("java/lang/Long"),
        ]);
        let mut collector = Self {
            types: method.state().types(),
            uses,
            error: None,
        };
        collector.visit_node(method.body());
        match collector.error {
            Some(error) => Err(error.into()),
            None => Ok(collector.uses),
        }
    }

    fn insert(&mut self, ty: &ArgType) {
        let mut pending = vec![ty];
        while let Some(ty) = pending.pop() {
            if !ty.is_known() {
                continue;
            }
            self.uses.insert(ty.clone());
            if let ArgType::Array(element) = ty {
                pending.push(element);
            }
        }
    }
}

impl SemanticVisitor for MethodTypeUses<'_> {
    fn enter_node(&mut self, node: &SemanticNode) {
        let catches = match node {
            SemanticNode::Try { catches, .. } => Some(catches.as_slice()),
            _ => None,
        };
        if let Some(catches) = catches {
            for ty in catches
                .iter()
                .flat_map(|catch| catch.exception_types.iter())
            {
                self.insert(ty);
            }
        }
    }

    fn enter_operation(&mut self, operation: &crate::ir::SemanticOperation) {
        if let Some(result) = &operation.result {
            match self.types.register_type(result).cloned() {
                Ok(ty) => self.insert(&ty),
                Err(error) if self.error.is_none() => self.error = Some(error),
                Err(_) => {}
            }
        }
        self.insert_option(operation.payload.class_type.as_ref());
        self.insert_option(operation.payload.cast_type.as_ref());
        match operation.payload.reference.as_ref() {
            Some(MemberReference::Field(field)) => {
                self.insert(&field.owner);
                self.insert(&field.field_type);
            }
            Some(MemberReference::Method(method)) => {
                self.insert(&method.owner);
                for ty in &method.descriptor.parameters {
                    self.insert(ty);
                }
                self.insert(&method.descriptor.return_type);
            }
            None => {}
        }
    }

    fn visit_register(&mut self, register: &crate::ir::RegisterArg) {
        match self.types.register_type(register).cloned() {
            Ok(ty) => self.insert(&ty),
            Err(error) if self.error.is_none() => self.error = Some(error),
            Err(_) => {}
        }
    }

    fn visit_binding(
        &mut self,
        _kind: crate::ir::SemanticBindingKind,
        register: &crate::ir::RegisterArg,
    ) {
        self.insert(&register.ty);
        self.visit_register(register);
    }
}

impl MethodTypeUses<'_> {
    fn insert_option(&mut self, ty: Option<&ArgType>) {
        if let Some(ty) = ty {
            self.insert(ty);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::analysis::ClassHierarchyIndex;
    use crate::ir::{
        Block, InsnArg, InsnNode, MethodContext, MethodDescriptor, RegionKind, RegisterArg, CFG,
    };
    use crate::JavaDecompiler;

    fn trivial_int_cfg() -> CFG {
        let method = MethodContext::new(
            ArgType::object("java/lang/Object"),
            "answer",
            MethodDescriptor {
                parameters: Vec::new(),
                return_type: ArgType::INT,
            },
            true,
        );
        let mut cfg = CFG::with_method(method);
        cfg.registers = 1;
        let dest = RegisterArg::new_ssa(0, 0, ArgType::INT);
        let mut block = Block::new(0u32);
        block.push(InsnNode::const_val(dest.clone(), 1, ArgType::INT));
        block.push(InsnNode::return_value(InsnArg::Reg(dest)));
        cfg.add_block(block);
        cfg
    }

    fn print_method(cfg: &mut CFG) -> String {
        JavaDecompiler::new(Default::default())
            .generate_method(cfg)
            .expect("printed method declaration")
    }

    #[test]
    fn straight_line_printed_text_matches_full_passes() {
        let mut early = trivial_int_cfg();
        let mut full = early.clone();
        let early_text = print_method(&mut early);
        let full_text = crate::ir::disable_trivial_early_returns(|| print_method(&mut full));
        assert_eq!(early_text, full_text);
        assert!(early_text.contains("static int answer()"), "{early_text}");
        assert!(early_text.contains("return 1"), "{early_text}");
    }

    #[test]
    fn straight_line_pipeline_still_builds_a_method_root() {
        let mut cfg = trivial_int_cfg();
        let hierarchy = ClassHierarchyIndex::default();
        let values = CfgPipeline::new(&hierarchy)
            .analyze(&mut cfg)
            .expect("cfg/ssa")
            .values;
        assert!(crate::ir::is_straight_line(&cfg, &values));
        let analysis = ExceptionAnalyzer::new(&cfg, &values, &hierarchy)
            .analyze()
            .expect("empty exception analysis");
        let graph = RegionGraphBuilder::new(&cfg, &analysis, &values)
            .build()
            .expect("region graph");
        let root = graph
            .tree()
            .region(graph.tree().root())
            .expect("method root");
        assert!(matches!(root.kind, RegionKind::Method));
        assert_eq!(root.blocks.len(), cfg.blocks.len());
    }
}
