{
  "targets": [
    {
      "target_name": "pcap_parser",
      "sources": ["pcap_parser.cpp"],
      "include_dirs": [
        "node_modules/node-addon-api",
        "/usr/include"
      ],
      "libraries": [
        "-lpcap"
      ],
      "cflags": [
        "-std=c++17",
        "-fexceptions"
      ],
      "cflags_cc": [
        "-std=c++17",
        "-fexceptions"
      ],
      "defines": ["NAPI_CPP_EXCEPTIONS"]
    }
  ]
}
