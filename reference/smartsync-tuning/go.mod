module openappsec.io/smartsync-tuning

go 1.18

replace (
	openappsec.io/configuration => ./dependencies/openappsec.io/configuration
	openappsec.io/ctxutils => ./dependencies/openappsec.io/ctxutils
	openappsec.io/errors => ./dependencies/openappsec.io/errors
	openappsec.io/health => ./dependencies/openappsec.io/health
	openappsec.io/httputils => ./dependencies/openappsec.io/httputils
	openappsec.io/jsonschema => ./dependencies/openappsec.io/jsonschema
	openappsec.io/log => ./dependencies/openappsec.io/log
	openappsec.io/tracer => ./dependencies/openappsec.io/tracer
)

require (
	github.com/go-chi/chi v4.1.2+incompatible
	github.com/google/uuid v1.3.0
	github.com/google/wire v0.5.0
	github.com/lib/pq v1.10.7
	github.com/spf13/viper v1.14.0 // indirect
	golang.org/x/sync v0.1.0
	google.golang.org/api v0.102.0
	k8s.io/apimachinery v0.17.0
	k8s.io/client-go v0.17.0
	openappsec.io/configuration v0.8.1
	openappsec.io/ctxutils v0.6.0
	openappsec.io/errors v0.8.0
	openappsec.io/health v0.5.1
	openappsec.io/httputils v0.12.1
	openappsec.io/log v0.10.0
	openappsec.io/tracer v0.6.0
)

require gopkg.in/yaml.v2 v2.4.0

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/fsnotify/fsnotify v1.6.0 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/google/gofuzz v1.0.0 // indirect
	github.com/hashicorp/hcl v1.0.0 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/magiconair/properties v1.8.6 // indirect
	github.com/mitchellh/mapstructure v1.5.0 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/opentracing/opentracing-go v1.2.0 // indirect
	github.com/pelletier/go-toml v1.9.5 // indirect
	github.com/pelletier/go-toml/v2 v2.0.6 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/sirupsen/logrus v1.9.0 // indirect
	github.com/spf13/afero v1.9.3 // indirect
	github.com/spf13/cast v1.5.0 // indirect
	github.com/spf13/jwalterweatherman v1.1.0 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/subosito/gotenv v1.4.1 // indirect
	github.com/uber/jaeger-client-go v2.30.0+incompatible // indirect
	github.com/uber/jaeger-lib v2.4.1+incompatible // indirect
	go.uber.org/atomic v1.10.0 // indirect
	golang.org/x/crypto v0.3.0 // indirect
	golang.org/x/net v0.2.0 // indirect
	golang.org/x/oauth2 v0.0.0-20221014153046-6fdb5e3db783 // indirect
	golang.org/x/sys v0.2.0 // indirect
	golang.org/x/term v0.2.0 // indirect
	golang.org/x/text v0.4.0 // indirect
	golang.org/x/time v0.0.0-20220609170525-579cf78fd858 // indirect
	golang.org/x/xerrors v0.0.0-20220907171357-04be3eba64a2 // indirect
	google.golang.org/appengine v1.6.7 // indirect
	google.golang.org/protobuf v1.28.1 // indirect
	gopkg.in/inf.v0 v0.9.1 // indirect
	gopkg.in/ini.v1 v1.67.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	k8s.io/api v0.17.0 // indirect
	k8s.io/klog v1.0.0 // indirect
	k8s.io/utils v0.0.0-20191114184206-e782cd3c129f // indirect
	sigs.k8s.io/yaml v1.1.0 // indirect
)
