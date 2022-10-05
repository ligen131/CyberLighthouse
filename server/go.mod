module server

go 1.13

require (
	CyberLighthouse v0.0.0-00010101000000-000000000000
	client v0.0.0-00010101000000-000000000000
	github.com/spf13/cobra v1.2.1
)

replace CyberLighthouse => ../src/

replace client => ../client/
