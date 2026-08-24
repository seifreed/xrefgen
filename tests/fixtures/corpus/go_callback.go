package main
func apply(callback func(int) int, value int) int { return callback(value) }
func add(value int) int { return value + 1 }
func main() { if apply(add, 4) != 5 { panic("bad") } }
