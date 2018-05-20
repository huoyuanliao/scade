use std::collections::HashSet;
use track::Port;

type PortSet = HashSet<Port>;

pub struct ServicePortList(PortSet);
pub struct MalWarePortList(PortSet);

impl ServicePortList {
    pub fn new() -> Self {
        ServicePortList(PortSet::new())
    }
    pub fn contains_port(&self, port: &Port) -> bool {
        return self.0.contains(port);
    }
    pub fn add_port(&mut self, port: Port) -> bool {
        self.0.insert(port)
    }
}

impl MalWarePortList {
    pub fn new() -> Self {
        MalWarePortList(PortSet::new())
    }
    pub fn contains_port(&self, port: &Port) -> bool {
        return self.0.contains(port);
    }
    pub fn add_port(&mut self, port: Port) -> bool {
        self.0.insert(port)
    }
}