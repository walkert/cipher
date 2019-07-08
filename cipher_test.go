package cipher

import (
	"reflect"
	"strings"
	"testing"
)

func TestRandomString(t *testing.T) {
	got := RandomString(10)
	if len(got) != 10 {
		t.Fatalf("Expected 10 chars but got %d\n", len(got))
	}
	next := RandomString(10)
	if got == next {
		t.Fatalf("Got two identical random strings - seed problem")
	}
}

func TestEncryptString(t *testing.T) {
	type args struct {
		data string
		salt string
		pass string
	}
	tests := []struct {
		name      string
		args      args
		want      []byte
		wantErr   bool
		errString string
		breakSalt bool
		breakPass bool
	}{
		{
			"GoodVals",
			args{"mypassword", "salt1", "encpass1"},
			[]byte{119, 224, 79, 221, 202, 110, 165, 151, 125, 222, 121, 202, 26, 73, 252, 196},
			false,
			"",
			false,
			false,
		},
		{
			"Empty salt",
			args{"mypassword", "", "encpass1"},
			[]byte{84, 18, 235, 69, 20, 130, 206, 198, 243, 25, 42, 218, 239, 80, 164, 189},
			false,
			"",
			false,
			false,
		},
		{
			"Empty pass",
			args{"mypassword", "salt1", ""},
			[]byte{234, 19, 90, 183, 197, 106, 14, 43, 226, 229, 55, 228, 94, 35, 215, 225},
			false,
			"",
			false,
			false,
		},
		{
			"Empty salt/pass",
			args{"mypassword", "", ""},
			[]byte{140, 95, 96, 125, 34, 218, 206, 57, 129, 190, 146, 185, 130, 129, 199, 226},
			false,
			"",
			false,
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := EncryptString(tt.args.data, tt.args.salt, tt.args.pass)
			if err != nil {
				if !tt.wantErr {
					t.Errorf("Unexpected error: %v", err)
					return
				}
				if !strings.Contains(err.Error(), tt.errString) {
					t.Fatalf("Expected error string to contain '%s', but got: %v", tt.errString, err)
				}
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("EncryptString() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDecryptString(t *testing.T) {
	type args struct {
		data string
		salt string
		pass string
	}
	tests := []struct {
		name      string
		args      args
		want      string
		wantErr   bool
		errString string
		breakSalt bool
		breakPass bool
	}{
		{
			"GoodVals",
			args{"mypassword", "salt1", "encpass1"},
			"mypassword",
			false,
			"",
			false,
			false,
		},
		{
			"NoSalt",
			args{"mypassword", "", "encpass1"},
			"mypassword",
			false,
			"",
			false,
			false,
		},
		{
			"NoPass",
			args{"mypassword", "salt1", ""},
			"mypassword",
			false,
			"",
			false,
			false,
		},
		{
			"NoSaltPass",
			args{"mypassword", "", ""},
			"mypassword",
			false,
			"",
			false,
			false,
		},
		{
			"BadSalt",
			args{"mypassword", "salt1", "encpass1"},
			"mypassword",
			true,
			"bad salt/pass",
			true,
			false,
		},
		{
			"BadPass",
			args{"mypassword", "salt1", "encpass1"},
			"mypassword",
			true,
			"bad salt/pass",
			false,
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encrypted, err := EncryptString(tt.args.data, tt.args.salt, tt.args.pass)
			if err != nil {
				t.Errorf("Unexpected error encrypting string: %v", err)
				return
			}
			var decsalt string
			if tt.breakSalt {
				decsalt = "badSalt"
			} else {
				decsalt = tt.args.salt
			}
			var decpass string
			if tt.breakPass {
				decpass = "badPass"
			} else {
				decpass = tt.args.pass
			}
			got, err := DecryptString(string(encrypted), decsalt, decpass)
			if err != nil {
				if !tt.wantErr {
					t.Errorf("Unexpected error: %v", err)
					return
				}
				if !strings.Contains(err.Error(), tt.errString) {
					t.Fatalf("Expected error string to contain '%s', but got: %v", tt.errString, err)
				}
				return
			}
			if string(got) != tt.want {
				t.Errorf("DecryptString() = %v, want %v", string(got), tt.want)
			}
		})
	}
}

func TestEmptyBytes(t *testing.T) {
	_, err := DecryptBytes([]byte{}, "test", "test")
	if err == nil {
		t.Fatal("expected error but got none")
	}
}
