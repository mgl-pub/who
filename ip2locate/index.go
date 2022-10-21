package ip2locate

import (
	"fmt"
	"github.com/ip2location/ip2location-go/v9"
	"who/common"
	"who/model"
)

type ip2region struct {
}

var Ip2Location = ip2region{}

// GetForeignRegion 获取国外地址，这个比较准 内的就不准
func (receiver ip2region) GetForeignRegion(ip string) *model.IpInfoVo {
	db, err := ip2location.OpenDB(common.Utils.GetIpDataPath() + "/IP2LOCATION.BIN")
	if err != nil {
		fmt.Print(err)
		return nil
	}
	results, err := db.Get_all(ip)

	if err != nil {
		fmt.Print(err)
		return nil
	}

	fmt.Printf("country_short: %s\n", results.Country_short)
	fmt.Printf("country_long: %s\n", results.Country_long)
	fmt.Printf("region: %s\n", results.Region)
	fmt.Printf("city: %s\n", results.City)
	fmt.Printf("isp: %s\n", results.Isp)
	fmt.Printf("latitude: %f\n", results.Latitude)
	fmt.Printf("longitude: %f\n", results.Longitude)
	fmt.Printf("domain: %s\n", results.Domain)
	fmt.Printf("zipcode: %s\n", results.Zipcode)
	fmt.Printf("timezone: %s\n", results.Timezone)
	fmt.Printf("netspeed: %s\n", results.Netspeed)
	fmt.Printf("iddcode: %s\n", results.Iddcode)
	fmt.Printf("areacode: %s\n", results.Areacode)
	fmt.Printf("weatherstationcode: %s\n", results.Weatherstationcode)
	fmt.Printf("weatherstationname: %s\n", results.Weatherstationname)
	fmt.Printf("mcc: %s\n", results.Mcc)
	fmt.Printf("mnc: %s\n", results.Mnc)
	fmt.Printf("mobilebrand: %s\n", results.Mobilebrand)
	fmt.Printf("elevation: %f\n", results.Elevation)
	fmt.Printf("usagetype: %s\n", results.Usagetype)
	fmt.Printf("addresstype: %s\n", results.Addresstype)
	fmt.Printf("category: %s\n", results.Category)
	fmt.Printf("api version: %s\n", ip2location.Api_version())

	vo := new(model.IpInfoVo)

	vo.Ip = ip
	vo.City = results.City
	vo.Region = results.Region
	vo.CountryShort = results.Country_short
	vo.CountryLong = results.Country_long
	vo.Latitude = results.Latitude
	vo.Longitude = results.Longitude
	vo.Zipcode = results.Zipcode
	db.Close()
	return vo
}
