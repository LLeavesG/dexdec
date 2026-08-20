use crate::ir::{SemanticFoldError, SemanticFolder, SemanticNode, SemanticSiteId, SemanticVisitor};

pub(crate) struct SemanticSiteNumbering {
    next: u64,
}

impl SemanticSiteNumbering {
    /// Site ids in the same node order `assign` writes them.
    pub(crate) fn fingerprint(root: &SemanticNode) -> Vec<u64> {
        let mut visitor = SiteFingerprint { sites: Vec::new() };
        visitor.visit_node(root);
        visitor.sites
    }

    pub(crate) fn assign(root: &mut SemanticNode) -> Result<(), SemanticFoldError> {
        let body = std::mem::replace(root, SemanticNode::Empty);
        *root = Self { next: 0 }.fold_node(body)?;
        Ok(())
    }
}

impl SemanticFolder for SemanticSiteNumbering {
    type Error = SemanticFoldError;

    fn finish_node(&mut self, mut node: SemanticNode) -> Result<SemanticNode, Self::Error> {
        match &mut node {
            SemanticNode::BasicBlock(block) => {
                for statement in &mut block.statements {
                    statement.site = Some(self.next_site());
                }
            }
            SemanticNode::For {
                init,
                condition,
                update,
                ..
            } => {
                init.site = Some(self.next_site());
                condition.site = Some(self.next_site());
                update.site = Some(self.next_site());
            }
            SemanticNode::If { condition, .. } => {
                condition.site = Some(self.next_site());
            }
            SemanticNode::Loop { test, .. } => {
                test.condition.site = Some(self.next_site());
            }
            SemanticNode::ForEach { iterable, .. } => {
                iterable.site = Some(self.next_site());
            }
            SemanticNode::Switch { selector, .. } => {
                selector.site = Some(self.next_site());
            }
            SemanticNode::Synchronized { lock, .. } => {
                lock.site = Some(self.next_site());
            }
            SemanticNode::Leave(leave) => {
                leave.site = Some(self.next_site());
            }
            _ => {}
        }
        Ok(node)
    }
}

struct SiteFingerprint {
    sites: Vec<u64>,
}

impl SiteFingerprint {
    fn push(&mut self, site: Option<SemanticSiteId>) {
        if let Some(site) = site {
            self.sites.push(site.0);
        }
    }
}

impl SemanticVisitor for SiteFingerprint {
    fn enter_node(&mut self, node: &SemanticNode) {
        match node {
            SemanticNode::BasicBlock(block) => {
                for statement in &block.statements {
                    self.push(statement.site);
                }
            }
            SemanticNode::For {
                init,
                condition,
                update,
                ..
            } => {
                self.push(init.site);
                self.push(condition.site);
                self.push(update.site);
            }
            SemanticNode::If { condition, .. } => self.push(condition.site),
            SemanticNode::Loop { test, .. } => self.push(test.condition.site),
            SemanticNode::ForEach { iterable, .. } => self.push(iterable.site),
            SemanticNode::Switch { selector, .. } => self.push(selector.site),
            SemanticNode::Synchronized { lock, .. } => self.push(lock.site),
            SemanticNode::Leave(leave) => self.push(leave.site),
            _ => {}
        }
    }
}

impl SemanticSiteNumbering {
    fn next_site(&mut self) -> SemanticSiteId {
        let site = SemanticSiteId(self.next);
        self.next += 1;
        site
    }
}
