package types

import (
	"errors"
	"strings"

	"github.com/coreos/ignition/config/validate/report"
)

var (
	ErrInvalidFlannelTag = errors.New("invalid flannel version")
)

type Flannel struct {
	Version FlannelVersion `yaml:"version"`
	Options
}

type flannelCommon Flannel

type FlannelVersion string

func (fv FlannelVersion) Validate() report.Report {
	validTags := []string{
		"v0.6.2",
		"v0.6.1",
		"v0.6.0",
		"v0.5.6",
		"v0.5.5",
		"v0.5.4",
		"v0.5.3",
		"v0.5.2",
		"v0.5.1",
		"v0.5.0",
	}
	for _, tag := range validTags {
		if string(fv) == tag {
			return report.Report{}
		}
	}
	return report.ReportFromError(ErrInvalidFlannelTag, report.EntryError)
}

func (flannel *Flannel) UnmarshalYAML(unmarshal func(interface{}) error) error {
	t := flannelCommon(*flannel)
	if err := unmarshal(&t); err != nil {
		return err
	}
	*flannel = Flannel(t)

	if strings.HasPrefix(string(flannel.Version), "v0.6") {
		o := Flannel06{}
		if err := unmarshal(&o); err != nil {
			return err
		}
		flannel.Options = o
	} else if strings.HasPrefix(string(flannel.Version), "v0.5") {
		o := Flannel05{}
		if err := unmarshal(&o); err != nil {
			return err
		}
		flannel.Options = o
	}
	return nil
}

// Flannel06 represents flannel options for version 0.6.x. Don't embed Flannel05 because
// the yaml parser doesn't handle embedded structs
type Flannel06 struct {
	EtcdUsername  string `yaml:"etcd_username"  env:"FLANNELD_ETCD_USERNAME"`
	EtcdPassword  string `yaml:"etcd_password"  env:"FLANNELD_ETCD_PASSWORD"`
	EtcdEndpoints string `yaml:"etcd_endpoints" env:"FLANNELD_ETCD_ENDPOINTS"`
	EtcdCAFile    string `yaml:"etcd_cafile"    env:"FLANNELD_ETCD_CAFILE"`
	EtcdCertFile  string `yaml:"etcd_certfile"  env:"FLANNELD_ETCD_CERTFILE"`
	EtcdKeyFile   string `yaml:"etcd_keyfile"   env:"FLANNELD_ETCD_KEYFILE"`
	EtcdPrefix    string `yaml:"etcd_prefix"    env:"FLANNELD_ETCD_PREFIX"`
	IPMasq        string `yaml:"ip_masq"        env:"FLANNELD_IP_MASQ"`
	SubnetFile    string `yaml:"subnet_file"    env:"FLANNELD_SUBNET_FILE"`
	Iface         string `yaml:"interface"      env:"FLANNELD_IFACE"`
	PublicIP      string `yaml:"public_ip"      env:"FLANNELD_PUBLIC_IP"`
}

type Flannel05 struct {
	EtcdEndpoints string `yaml:"etcd_endpoints" env:"FLANNELD_ETCD_ENDPOINTS"`
	EtcdCAFile    string `yaml:"etcd_cafile"    env:"FLANNELD_ETCD_CAFILE"`
	EtcdCertFile  string `yaml:"etcd_certfile"  env:"FLANNELD_ETCD_CERTFILE"`
	EtcdKeyFile   string `yaml:"etcd_keyfile"   env:"FLANNELD_ETCD_KEYFILE"`
	EtcdPrefix    string `yaml:"etcd_prefix"    env:"FLANNELD_ETCD_PREFIX"`
	IPMasq        string `yaml:"ip_masq"        env:"FLANNELD_IP_MASQ"`
	SubnetFile    string `yaml:"subnet_file"    env:"FLANNELD_SUBNET_FILE"`
	Iface         string `yaml:"interface"      env:"FLANNELD_IFACE"`
	PublicIP      string `yaml:"public_ip"      env:"FLANNELD_PUBLIC_IP"`
}
