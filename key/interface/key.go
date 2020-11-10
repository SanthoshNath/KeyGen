package key

type Key interface {
	Generate() error
	Export(filepath string) error
}
