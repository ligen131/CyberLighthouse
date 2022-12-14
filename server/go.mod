module server

go 1.13

require (
	CyberLighthouse v0.0.0-00010101000000-000000000000
	client v0.0.0-00010101000000-000000000000
	github.com/gogf/greuse v1.1.0
	github.com/spf13/cobra v1.2.1
	go.mongodb.org/mongo-driver v1.10.3
)

replace CyberLighthouse => ../src/

replace client => ../client/
