package model

type IpInfoVo struct {
	Ip           string
	CountryShort string
	CountryLong  string
	Region       string
	City         string
	Latitude     float32
	Longitude    float32
	Timezone     string
	Zipcode      string
}

type Page struct {
	List []interface{}
	Tile string
	Data interface{} `json:"data"`
}

type Data struct {
	LocalIps     []string
	Name         string
	HostName     string
	Headers      []Header
	ClientIp     string
	ClientRegion string
}

type Header struct {
	Key   string
	Value string
}
