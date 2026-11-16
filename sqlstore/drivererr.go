package sqlstore

import (
	"errors"
	"reflect"
)

func driverCode(err error, typeName, field string) (int64, bool) {
	for err != nil {
		if code, ok := codeOf(err, typeName, field); ok {
			return code, true
		}
		if joined, ok := err.(interface{ Unwrap() []error }); ok {
			for _, inner := range joined.Unwrap() {
				if code, found := driverCode(inner, typeName, field); found {
					return code, true
				}
			}
			return 0, false
		}
		err = errors.Unwrap(err)
	}
	return 0, false
}

func codeOf(err error, typeName, field string) (int64, bool) {
	value := reflect.ValueOf(err)
	for value.Kind() == reflect.Pointer && !value.IsNil() {
		value = value.Elem()
	}
	if value.Kind() != reflect.Struct || value.Type().Name() != typeName {
		return 0, false
	}
	number := value.FieldByName(field)
	switch {
	case !number.IsValid() || !number.CanInterface():
		return 0, false
	case number.CanInt():
		return number.Int(), true
	case number.CanUint():
		return int64(number.Uint()), true //nolint:gosec
	}
	return 0, false
}
