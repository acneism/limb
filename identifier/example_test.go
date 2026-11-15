package identifier_test

import (
	"fmt"

	"github.com/acneism/limb/identifier"
)

func ExampleEmail() {
	email := identifier.Email()

	value, err := email.Normalize("  Alice@Example.COM ")
	fmt.Println(value, err)

	value, err = email.Normalize("user@пример.рф")
	fmt.Println(value, err)

	_, err = email.Normalize("Alice <alice@example.com>")
	fmt.Println(err)
	// Output:
	// alice@example.com <nil>
	// user@xn--e1afmkfd.xn--p1ai <nil>
	// display names are not allowed in an e-mail address
}

func ExampleUsername() {
	username := identifier.Username()

	value, err := username.Normalize("  Alice_01 ")
	fmt.Println(value, err)

	_, err = username.Normalize("12345")
	fmt.Println(err)

	_, err = username.Normalize("al")
	fmt.Println(err)
	// Output:
	// alice_01 <nil>
	// nickname must not consist of digits only
	// value is too short: at least 3 characters required
}

func ExampleCustom() {
	employee := identifier.Custom("employee_id",
		identifier.Pattern(`[0-9]{6}`),
		identifier.LoginAllowed(),
	)

	value, err := employee.Normalize(" 004217 ")
	fmt.Println(employee.Name(), employee.IsLogin(), value, err)

	_, err = employee.Normalize("4217")
	fmt.Println(err)
	// Output:
	// employee_id true 004217 <nil>
	// value has an invalid format
}

func ExampleResolve() {
	types := []identifier.Type{identifier.Email(), identifier.Username()}

	for _, login := range []string{"Alice@Example.com", "Alice_01", "+15551234567"} {
		typ, value, err := identifier.Resolve(types, login)
		if err != nil {
			fmt.Println("rejected:", login)
			continue
		}
		fmt.Println(typ.Name(), value)
	}
	// Output:
	// email alice@example.com
	// username alice_01
	// rejected: +15551234567
}
