module itops/agent

go 1.24.0

require golang.org/x/sys v0.38.0

// Bản sao golang.org/x/sys (từ github.com/golang/sys, tag v0.38.0) đã đưa vào thư mục vendor/ –
// build không cần Internet. Muốn cập nhật: clone tag mới vào third_party/xsys rồi `go mod vendor`.
replace golang.org/x/sys => ./third_party/xsys
