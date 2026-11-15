package phone_test

import (
	"fmt"

	"github.com/acneism/limb/identifier"
	"github.com/acneism/limb/identifier/phone"
)

func ExampleNumber() {
	number := phone.Number("RU")

	value, err := number.Normalize("8 (926) 123-45-67")
	fmt.Println(value, err)

	value, err = number.Normalize("+1 650 253 0000")
	fmt.Println(value, err)

	_, err = number.Normalize("1-800-FLOWERS")
	fmt.Println(err)
	// Output:
	// +79261234567 <nil>
	// +16502530000 <nil>
	// invalid phone number
}

func ExampleNumber_resolve() {
	types := []identifier.Type{identifier.Email(), phone.Number("RU"), identifier.Username()}

	typ, value, _ := identifier.Resolve(types, "926 123 45 67")
	fmt.Println(typ.Name(), value)

	typ, value, _ = identifier.Resolve(types, "bob_1999")
	fmt.Println(typ.Name(), value)
	// Output:
	// phone +79261234567
	// username bob_1999
}
