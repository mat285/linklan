package config

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"regexp"
	"sort"
	"strconv"

	"github.com/mat285/linklan/log"
)

const (
	DefaultPrimaryCIDR   = "192.168.1.0/24"
	DefaultSecondaryCIDR = "10.69.0.0/16"
)

type Config struct {
	Lan        Lan     `yaml:"lan,omitempty" json:"lan,omitempty"`
	Interfaces []IFace `yaml:"interfaces,omitempty" json:"interfaces,omitempty"`
	Routing    Routing `yaml:"routing,omitempty" json:"routing,omitempty"`

	Logger log.Config `yaml:"logger,omitempty" json:"logger,omitempty"`
}

type Lan struct {
	CIDR          string `yaml:"cidr,omitempty" json:"cidr,omitempty"`
	Iface         string `yaml:"iface,omitempty" json:"iface,omitempty"`
	SecondaryCIDR string `yaml:"secondaryCidr,omitempty" json:"secondaryCidr,omitempty"`
}

type IFace struct {
	IFaceIndentifier `yaml:",inline" json:",inline"`
	Match            IFaceIndentifier `yaml:"match,omitempty" json:"match,omitempty"`
	IP               string           `yaml:"ip,omitempty" json:"ip,omitempty"`
	Priority         int              `yaml:"priority,omitempty" json:"priority,omitempty"`
	Disabled         bool             `yaml:"disabled,omitempty" json:"disabled,omitempty"`
	Speed            int              `yaml:"-" json:"-"` // Speed is not serialized, used internally
}

func (i IFace) MatchesName(name string) bool {
	if !i.Match.IsZero() {
		return i.Match.MatchesName(name, true)
	}
	return i.IFaceIndentifier.MatchesName(name, false)
}

type IFaceIndentifier struct {
	Name string `yaml:"name,omitempty" json:"name,omitempty"`
	Mac  string `yaml:"mac,omitempty" json:"mac,omitempty"`
}

func (i IFaceIndentifier) IsZero() bool {
	return i.Name == "" && i.Mac == ""
}

func (i IFaceIndentifier) MatchesName(name string, regex bool) bool {
	if regex {
		r, err := regexp.Compile(i.Name)
		if err != nil {
			return false // Invalid regex, treat as no match
		}
		return r.MatchString(name)
	}
	return i.Name == name
}

type Routing struct {
	AdditionalCIDRs []string `yaml:"additionalCidrs,omitempty" json:"additionalCidrs,omitempty"`
	Bonding         Bonding  `yaml:"bonding,omitempty" json:"bonding,omitempty"`
	Routes          []Route  `yaml:"routes,omitempty" json:"routes,omitempty"`
}

type Route struct {
	Destination string `yaml:"destination,omitempty" json:"destination,omitempty"`
	Iface       string `yaml:"iface,omitempty" json:"iface,omitempty"`
}

type Bonding struct {
	Mode          string   `yaml:"mode,omitempty" json:"mode,omitempty"`
	Ifaces        []string `yaml:"ifaces,omitempty" json:"ifaces,omitempty"`
	AllInterfaces bool     `yaml:"allInterfaces,omitempty" json:"allInterfaces,omitempty"`
	Enabled       bool     `yaml:"enabled,omitempty" json:"enabled,omitempty"`
}

func (c *Config) String() string {
	if c == nil {
		return "Config(nil)"
	}
	data, _ := json.Marshal(c)
	return string(data)
}

func (c *Config) SetDefaults() {
	if c.Lan.CIDR == "" {
		c.Lan.CIDR = DefaultPrimaryCIDR
	}
	if c.Lan.SecondaryCIDR == "" {
		c.Lan.SecondaryCIDR = DefaultSecondaryCIDR
	}
}

func (c *Config) Resolve(ctx context.Context) (context.Context, error) {
	c.SetDefaults()
	ctx = log.WithLogger(ctx, log.New(c.Logger))
	if _, err := ParseCidr(c.Lan.CIDR); err != nil {
		return nil, fmt.Errorf("invalid primary CIDR [%q]: %w", c.Lan.CIDR, err)
	}
	if _, err := ParseCidr(c.Lan.SecondaryCIDR); err != nil {
		return nil, fmt.Errorf("invalid secondary CIDR [%q]: %w", c.Lan.SecondaryCIDR, err)
	}

	// for i, cidr := range c.Lan.SecondaryCIDRs {
	// 	if _, err := ParseCidr(cidr); err != nil {
	// 		return nil, fmt.Errorf("invalid secondary CIDR  index %d [%q]: %w", i, cidr, err)
	// 	}
	// }

	for i, iface := range c.Interfaces {
		if iface.Match.IsZero() && iface.IFaceIndentifier.IsZero() {
			return nil, fmt.Errorf("interface %d must have either match or iface identifier set", i)
		}
		if !iface.Match.IsZero() && !iface.IFaceIndentifier.IsZero() {
			return nil, fmt.Errorf("interface %d cannot have both match and iface identifier set", i)
		}
		if !iface.Match.IsZero() {
			if iface.Match.Name != "" {
				_, err := regexp.Compile(iface.Match.Name)
				if err != nil {
					return nil, fmt.Errorf("invalid regex for interface %d [%q]: %w", i, iface.Match.Name, err)
				}
			}
			if iface.Match.Mac != "" {
				_, err := regexp.Compile(iface.Match.Mac)
				if err != nil {
					return nil, fmt.Errorf("invalid regex for MAC address in interface %d [%q]: %w", i, iface.Match.Mac, err)
				}
			}
		}
		if iface.IP != "" {
			valid := net.ParseIP(iface.IP)
			if valid == nil {
				return nil, fmt.Errorf("invalid IP for interface %d [%q]", i, iface.IP)
			}
		}
	}

	for i, route := range c.Routing.Routes {
		if route.Destination == "" {
			return nil, fmt.Errorf("route %d must have a destination", i)
		}
		if route.Iface == "" {
			return nil, fmt.Errorf("route %d must have an interface", i)
		}
		if _, err := ParseCidr(route.Destination); err != nil {
			return nil, fmt.Errorf("invalid route destination %d [%q]: %w", i, route.Destination, err)
		}
	}
	if c.Routing.Bonding.Enabled {
		return nil, fmt.Errorf("bonding is not supported yet")
	}
	return ctx, nil
}

func (c *Config) SortInterfaces(ifaces []string) {
	if len(c.Interfaces) == 0 {
		sort.Strings(ifaces)
		return
	}

	sortable := make([]IFace, len(ifaces))
	for i, ifaceName := range ifaces {
		for _, iface := range c.Interfaces {
			if iface.MatchesName(ifaceName) {
				sortable[i] = iface
				sortable[i].IFaceIndentifier.Name = ifaceName // Ensure the name is set
				data, err := os.ReadFile("/sys/class/net/" + ifaceName + "/speed")
				if err == nil {
					if speed, err := strconv.Atoi(string(data)); err == nil {
						sortable[i].Speed = speed
					}
				}
				break
			}
		}
		if sortable[i].IFaceIndentifier.IsZero() {
			// If no matching interface found, use a default IFace with zero values
			sortable[i] = IFace{
				IFaceIndentifier: IFaceIndentifier{Name: ifaceName},
				Priority:         0, // Default priority
			}
		}
	}
	sort.Slice(ifaces, func(i, j int) bool {
		if sortable[i].Priority == sortable[j].Priority {
			// if sortable[i].Speed == sortable[j].Speed {
			return sortable[i].IFaceIndentifier.Name < sortable[j].IFaceIndentifier.Name
			// }
			// return sortable[i].Speed > sortable[j].Speed // Higher speed first
		}
		return sortable[i].IFaceIndentifier.Name < sortable[j].IFaceIndentifier.Name
	})
}

func ParseCidr(cidr string) (string, error) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return "", err
	}
	bits, _ := ipNet.Mask.Size()
	switch bits {
	case 8, 16, 24:
	default:
		return "", fmt.Errorf("unsupported CIDR size: %s bits: %d", cidr, bits)
	}
	return ipNet.String(), nil
}
