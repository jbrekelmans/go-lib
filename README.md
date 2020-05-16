# Introduction
A collection of Go libraries:
1. [auth/google/compute](auth/google/compute): verification of Google Compute Engine identity JSON Web Tokens (see [Google's documentation](https://cloud.google.com/compute/docs/instances/verifying-instance-identity#verify_signature)). This is useful for applications that want to accept an authentication mechanism based on Google Cloud Platform's Identity Access Management infrastructure.
1. [test](test): logrus logging in tests. For example:
    ```go
    import "github.com/jbrekelmans/go-lib/test"
    
    func Test_MyTest(t *testing.T) {
        defer test.RedirectLogs(t).Dispose()
        // Any calls that MyTest makes to logrus's standard logger are forwarded to t.Logf.
        MyTest()
    }
    ```