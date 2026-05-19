module github.com/chainreactors/found

go 1.24.0

toolchain go1.24.3

require (
	github.com/chainreactors/fingers v1.2.0
	github.com/chainreactors/logs v0.0.0-20250312104344-9f30fa69d3c9
	github.com/chainreactors/neutron v0.0.0
	github.com/chainreactors/proton v0.0.0
	github.com/chainreactors/utils v0.0.0-20260507101628-fd69d955ae21
	github.com/jessevdk/go-flags v1.6.1
	github.com/yeka/zip v0.0.0-20231116150916-03d6312748a9
	gopkg.in/yaml.v3 v3.0.1
	sigs.k8s.io/yaml v1.6.0
)

require (
	github.com/Knetic/govaluate v3.0.0+incompatible // indirect
	github.com/STARRY-S/zip v0.2.3 // indirect
	github.com/andybalholm/brotli v1.2.0 // indirect
	github.com/bodgit/plumbing v1.3.0 // indirect
	github.com/bodgit/sevenzip v1.6.1 // indirect
	github.com/bodgit/windows v1.0.1 // indirect
	github.com/chainreactors/files v0.0.0-20240716182835-7884ee1e77f0 // indirect
	github.com/charlievieth/fastwalk v1.0.14 // indirect
	github.com/dsnet/compress v0.0.2-0.20230904184137-39efe44ab707 // indirect
	github.com/edsrzf/mmap-go v1.2.0 // indirect
	github.com/go-dedup/megophone v0.0.0-20170830025436-f01be21026f5 // indirect
	github.com/go-dedup/simhash v0.0.0-20170904020510-9ecaca7b509c // indirect
	github.com/go-dedup/text v0.0.0-20170907015346-8bb1b95e3cb7 // indirect
	github.com/gobwas/glob v0.2.3 // indirect
	github.com/golang/snappy v0.0.4 // indirect
	github.com/h2non/filetype v1.1.3 // indirect
	github.com/hashicorp/go-version v1.6.0 // indirect
	github.com/hashicorp/golang-lru/v2 v2.0.7 // indirect
	github.com/klauspost/compress v1.18.0 // indirect
	github.com/klauspost/pgzip v1.2.6 // indirect
	github.com/kr/pretty v0.3.1 // indirect
	github.com/mholt/archiver v3.1.1+incompatible // indirect
	github.com/mholt/archives v0.1.5 // indirect
	github.com/mikelolasagasti/xz v1.0.1 // indirect
	github.com/minio/minlz v1.0.1 // indirect
	github.com/mozillazg/go-pinyin v0.20.0 // indirect
	github.com/nwaples/rardecode v1.1.3 // indirect
	github.com/nwaples/rardecode/v2 v2.2.0 // indirect
	github.com/petar-dambovaliev/aho-corasick v0.0.0-20250424160509-463d218d4745 // indirect
	github.com/pierrec/lz4 v2.6.1+incompatible // indirect
	github.com/pierrec/lz4/v4 v4.1.22 // indirect
	github.com/sorairolake/lzip-go v0.3.8 // indirect
	github.com/spaolacci/murmur3 v1.1.0 // indirect
	github.com/spf13/afero v1.15.0 // indirect
	github.com/tetratelabs/wazero v1.9.0 // indirect
	github.com/twmb/murmur3 v1.1.8 // indirect
	github.com/ulikunitz/xz v0.5.15 // indirect
	github.com/wasilibs/go-re2 v1.10.0 // indirect
	github.com/wasilibs/wazero-helpers v0.0.0-20240620070341-3dff1577cd52 // indirect
	github.com/xi2/xz v0.0.0-20171230120015-48954b6210f8 // indirect
	go.yaml.in/yaml/v2 v2.4.2 // indirect
	go4.org v0.0.0-20230225012048-214862532bf5 // indirect
	golang.org/x/crypto v0.19.0 // indirect
	golang.org/x/sys v0.30.0 // indirect
	golang.org/x/text v0.29.0 // indirect
)

replace (
	github.com/chainreactors/neutron => ../neutron
	github.com/chainreactors/proton => ../proton
)
