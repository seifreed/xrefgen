trait Handler { fn run(&self, value: i32) -> i32; }
struct Add;
impl Handler for Add { fn run(&self, value: i32) -> i32 { value + 2 } }
fn main() { let handler: &dyn Handler = &Add; assert_eq!(handler.run(1), 3); }
