use crate::{ComposeError, ComposeFile, ComposeResult};
use std::collections::{HashMap, VecDeque};

#[derive(Debug, Clone)]
pub struct ServiceGraph {
    order: Vec<Vec<String>>,
}

impl ServiceGraph {
    pub fn from_compose(compose: &ComposeFile) -> ComposeResult<Self> {
        let mut indegree: HashMap<String, usize> = HashMap::new();
        let mut edges: HashMap<String, Vec<String>> = HashMap::new();

        for name in compose.services.keys() {
            indegree.insert(name.clone(), 0);
        }

        for (name, service) in &compose.services {
            if let Some(depends_on) = &service.depends_on {
                for dep in depends_on.iter() {
                    if !compose.services.contains_key(dep) {
                        return Err(ComposeError::Validation(format!(
                            "service '{name}' depends on unknown service '{dep}'"
                        )));
                    }
                    let entry = edges.entry(dep.clone()).or_default();
                    entry.push(name.clone());
                    if let Some(count) = indegree.get_mut(name) {
                        *count += 1;
                    }
                }
            }
        }

        let mut queue: VecDeque<String> = indegree
            .iter()
            .filter_map(|(name, count)| if *count == 0 { Some(name.clone()) } else { None })
            .collect();

        let mut order = Vec::new();
        let mut processed = 0usize;

        while !queue.is_empty() {
            let mut batch = Vec::new();
            let batch_len = queue.len();
            for _ in 0..batch_len {
                if let Some(node) = queue.pop_front() {
                    processed += 1;
                    batch.push(node.clone());
                    if let Some(children) = edges.get(&node) {
                        for child in children {
                            if let Some(count) = indegree.get_mut(child) {
                                *count = count.saturating_sub(1);
                                if *count == 0 {
                                    queue.push_back(child.clone());
                                }
                            }
                        }
                    }
                }
            }
            order.push(batch);
        }

        if processed != indegree.len() {
            return Err(ComposeError::Validation(
                "compose contains cyclic dependencies".to_string(),
            ));
        }

        Ok(Self { order })
    }

    pub fn start_batches(&self) -> Vec<Vec<String>> {
        self.order.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::ServiceGraph;
    use crate::ComposeFile;
    use std::collections::HashMap;

    #[test]
    fn builds_batches() {
        let content = r#"
version: "3.8"
services:
  web:
    image: nginx:latest
    depends_on:
      - api
  api:
    image: alpine:latest
    depends_on:
      - db
  db:
    image: postgres:14
"#;
        let compose = ComposeFile::parse(content, &HashMap::new()).expect("parse");
        let graph = ServiceGraph::from_compose(&compose).expect("graph");
        let batches = graph.start_batches();
        assert_eq!(batches.len(), 3);
        assert!(batches[0].contains(&"db".to_string()));
    }

    #[test]
    fn detects_cycles() {
        let content = r#"
version: "3.8"
services:
  web:
    image: nginx:latest
    depends_on:
      - api
  api:
    image: alpine:latest
    depends_on:
      - web
"#;
        let compose = ComposeFile::parse(content, &HashMap::new()).expect("parse");
        let err = ServiceGraph::from_compose(&compose).expect_err("cycle");
        let message = format!("{err}");
        assert!(message.contains("cyclic"));
    }
}
