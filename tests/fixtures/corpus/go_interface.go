package main
type Handler interface { Run(int) int }
type Add struct{}
func (Add) Run(value int) int { return value + 2 }
func main() { var handler Handler = Add{}; if handler.Run(1) != 3 { panic("bad") } }
