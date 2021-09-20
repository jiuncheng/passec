package tools

import "encoding/json"

type Passec struct {
	Name      string `json:"name"`
	CryptData string `json:"crypt_data"`
}

func NewPassec(name string, cryptData string) *Passec {
	return &Passec{
		Name:      name,
		CryptData: cryptData,
	}
}

func NewPassecFromJson(jsonData string) (*Passec, error) {
	newPassec := &Passec{}
	err := json.Unmarshal([]byte(jsonData), newPassec)
	if err != nil {
		return nil, err
	}

	return newPassec, nil
}

func (p *Passec) EncodeJson() (string, error) {
	jsonData, err := json.Marshal(p)
	if err != nil {
		return "", err
	}

	return string(jsonData), nil
}
