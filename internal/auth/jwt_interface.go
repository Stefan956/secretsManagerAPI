package auth

type JWT interface {
	Generate(username string) (string, error)
	Verify(token string) (*Claims, error)
}
