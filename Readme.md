# WildFly Security Testsuite - Information


# Project Structure

# Running Individual Tests

The test cases in this project make use of suites to dynamically register many
permutations of tests for each test case, this enables us to cover many more
permutations that we would by writing manual tests which is great for test
execution in CI, however when debugging or developing tests it may be more
desirable to restrict the test run down to a limited set of permutations.

The following system properties can be set when running a test case to filter
the tests dynamically registered.

- `TestFilter.TransportType`
- `TestFilter.HttpAuthenticationMechanism`
- `TestFilter.SaslAuthenticationMechanism`
- `TestFilter.TestName`

Each property takes a comma separate list of allowed values, if the property is
not specified it is assumed that all values are supported.