
pub enum Future<T> {
    Value(T),
    Thunk(Box<FnOnce() -> Future<T>>)
}

impl<T> Future<T> {
    pub fn step (&mut self) {
        match self {
            Future::Value(_) => (),
            Future::Thunk(_) => {
                let tmp = Future::Thunk(Box::new(|| panic!("bug"))); 
                match std::mem::replace(self, tmp) {
                    Future::Thunk(f) => {std::mem::replace(self, f());},
                    _ => panic!("bug"),
                }
            }
        }
    }
}
