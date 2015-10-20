/*
 * Copyright (c) 2015, NVIDIA CORPORATION. All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */
#ifndef __nv_gf106_mmu_hwref_h__
#define __nv_gf106_mmu_hwref_h__

#define NV_MMU_PDE_APERTURE_BIG                  (0*32+1):(0*32+0)
#define NV_MMU_PDE_APERTURE_BIG_INVALID                          0
#define NV_MMU_PDE_APERTURE_BIG_VIDEO_MEMORY                     1
#define NV_MMU_PDE_SIZE                          (0*32+3):(0*32+2)
#define NV_MMU_PDE_SIZE_FULL                                     0
#define NV_MMU_PDE_ADDRESS_BIG_SYS              (0*32+31):(0*32+4)
#define NV_MMU_PDE_APERTURE_SMALL                (1*32+1):(1*32+0)
#define NV_MMU_PDE_APERTURE_SMALL_INVALID                        0
#define NV_MMU_PDE_APERTURE_SMALL_VIDEO_MEMORY                   1
#define NV_MMU_PDE_VOL_SMALL                     (1*32+2):(1*32+2)
#define NV_MMU_PDE_VOL_BIG                       (1*32+3):(1*32+3)
#define NV_MMU_PDE_ADDRESS_SMALL_SYS            (1*32+31):(1*32+4)
#define NV_MMU_PDE_ADDRESS_SHIFT                                12
#define NV_MMU_PDE__SIZE                                         8
#define NV_MMU_PTE_VALID                         (0*32+0):(0*32+0)
#define NV_MMU_PTE_READ_ONLY                     (0*32+2):(0*32+2)
#define NV_MMU_PTE_ADDRESS_SYS                  (0*32+31):(0*32+4)
#define NV_MMU_PTE_VOL                           (1*32+0):(1*32+0)
#define NV_MMU_PTE_APERTURE                      (1*32+2):(1*32+1)
#define NV_MMU_PTE_APERTURE_VIDEO_MEMORY                         0
#define NV_MMU_PTE_COMPTAGLINE                 (1*32+28):(1*32+12)
#define NV_MMU_PTE_ADDRESS_SHIFT                                12
#define NV_MMU_PTE__SIZE                                         8
#define NV_MMU_PTE_KIND                         (1*32+11):(1*32+4)
#define NV_MMU_PTE_KIND_INVALID                               0xff
#define NV_MMU_PTE_KIND_PITCH                                    0
#define NV_MMU_PTE_KIND_Z16                                      1
#define NV_MMU_PTE_KIND_Z16_2C                                   2
#define NV_MMU_PTE_KIND_Z16_MS2_2C                               3
#define NV_MMU_PTE_KIND_Z16_MS4_2C                               4
#define NV_MMU_PTE_KIND_Z16_MS8_2C                               5
#define NV_MMU_PTE_KIND_Z16_MS16_2C                              6
#define NV_MMU_PTE_KIND_Z16_2Z                                   7
#define NV_MMU_PTE_KIND_Z16_MS2_2Z                               8
#define NV_MMU_PTE_KIND_Z16_MS4_2Z                               9
#define NV_MMU_PTE_KIND_Z16_MS8_2Z                              10
#define NV_MMU_PTE_KIND_Z16_MS16_2Z                             11
#define NV_MMU_PTE_KIND_Z16_4CZ                                 12
#define NV_MMU_PTE_KIND_Z16_MS2_4CZ                             13
#define NV_MMU_PTE_KIND_Z16_MS4_4CZ                             14
#define NV_MMU_PTE_KIND_Z16_MS8_4CZ                             15
#define NV_MMU_PTE_KIND_Z16_MS16_4CZ                            16
#define NV_MMU_PTE_KIND_S8Z24                                   17
#define NV_MMU_PTE_KIND_S8Z24_1Z                                18
#define NV_MMU_PTE_KIND_S8Z24_MS2_1Z                            19
#define NV_MMU_PTE_KIND_S8Z24_MS4_1Z                            20
#define NV_MMU_PTE_KIND_S8Z24_MS8_1Z                            21
#define NV_MMU_PTE_KIND_S8Z24_MS16_1Z                           22
#define NV_MMU_PTE_KIND_S8Z24_2CZ                               23
#define NV_MMU_PTE_KIND_S8Z24_MS2_2CZ                           24
#define NV_MMU_PTE_KIND_S8Z24_MS4_2CZ                           25
#define NV_MMU_PTE_KIND_S8Z24_MS8_2CZ                           26
#define NV_MMU_PTE_KIND_S8Z24_MS16_2CZ                          27
#define NV_MMU_PTE_KIND_S8Z24_2CS                               28
#define NV_MMU_PTE_KIND_S8Z24_MS2_2CS                           29
#define NV_MMU_PTE_KIND_S8Z24_MS4_2CS                           30
#define NV_MMU_PTE_KIND_S8Z24_MS8_2CS                           31
#define NV_MMU_PTE_KIND_S8Z24_MS16_2CS                          32
#define NV_MMU_PTE_KIND_S8Z24_4CSZV                           0x21
#define NV_MMU_PTE_KIND_S8Z24_MS2_4CSZV                       0x22
#define NV_MMU_PTE_KIND_S8Z24_MS4_4CSZV                       0x23
#define NV_MMU_PTE_KIND_S8Z24_MS8_4CSZV                       0x24
#define NV_MMU_PTE_KIND_S8Z24_MS16_4CSZV                      0x25
#define NV_MMU_PTE_KIND_V8Z24_MS4_VC12                        0x26
#define NV_MMU_PTE_KIND_V8Z24_MS4_VC4                         0x27
#define NV_MMU_PTE_KIND_V8Z24_MS8_VC8                         0x28
#define NV_MMU_PTE_KIND_V8Z24_MS8_VC24                        0x29
#define NV_MMU_PTE_KIND_V8Z24_MS4_VC12_1ZV                    0x2e
#define NV_MMU_PTE_KIND_V8Z24_MS4_VC4_1ZV                     0x2f
#define NV_MMU_PTE_KIND_V8Z24_MS8_VC8_1ZV                     0x30
#define NV_MMU_PTE_KIND_V8Z24_MS8_VC24_1ZV                    0x31
#define NV_MMU_PTE_KIND_V8Z24_MS4_VC12_2CS                    0x32
#define NV_MMU_PTE_KIND_V8Z24_MS4_VC4_2CS                     0x33
#define NV_MMU_PTE_KIND_V8Z24_MS8_VC8_2CS                     0x34
#define NV_MMU_PTE_KIND_V8Z24_MS8_VC24_2CS                    0x35
#define NV_MMU_PTE_KIND_V8Z24_MS4_VC12_2CZV                   0x3a
#define NV_MMU_PTE_KIND_V8Z24_MS4_VC4_2CZV                    0x3b
#define NV_MMU_PTE_KIND_V8Z24_MS8_VC8_2CZV                    0x3c
#define NV_MMU_PTE_KIND_V8Z24_MS8_VC24_2CZV                   0x3d
#define NV_MMU_PTE_KIND_V8Z24_MS4_VC12_2ZV                    0x3e
#define NV_MMU_PTE_KIND_V8Z24_MS4_VC4_2ZV                     0x3f
#define NV_MMU_PTE_KIND_V8Z24_MS8_VC8_2ZV                     0x40
#define NV_MMU_PTE_KIND_V8Z24_MS8_VC24_2ZV                    0x41
#define NV_MMU_PTE_KIND_V8Z24_MS4_VC12_4CSZV                  0x42
#define NV_MMU_PTE_KIND_V8Z24_MS4_VC4_4CSZV                   0x43
#define NV_MMU_PTE_KIND_V8Z24_MS8_VC8_4CSZV                   0x44
#define NV_MMU_PTE_KIND_V8Z24_MS8_VC24_4CSZV                  0x45
#define NV_MMU_PTE_KIND_Z24S8                                 0x46
#define NV_MMU_PTE_KIND_Z24S8_1Z                              0x47
#define NV_MMU_PTE_KIND_Z24S8_MS2_1Z                          0x48
#define NV_MMU_PTE_KIND_Z24S8_MS4_1Z                          0x49
#define NV_MMU_PTE_KIND_Z24S8_MS8_1Z                          0x4a
#define NV_MMU_PTE_KIND_Z24S8_MS16_1Z                         0x4b
#define NV_MMU_PTE_KIND_Z24S8_2CS                             0x4c
#define NV_MMU_PTE_KIND_Z24S8_MS2_2CS                         0x4d
#define NV_MMU_PTE_KIND_Z24S8_MS4_2CS                         0x4e
#define NV_MMU_PTE_KIND_Z24S8_MS8_2CS                         0x4f
#define NV_MMU_PTE_KIND_Z24S8_MS16_2CS                        0x50
#define NV_MMU_PTE_KIND_Z24S8_2CZ                             0x51
#define NV_MMU_PTE_KIND_Z24S8_MS2_2CZ                         0x52
#define NV_MMU_PTE_KIND_Z24S8_MS4_2CZ                         0x53
#define NV_MMU_PTE_KIND_Z24S8_MS8_2CZ                         0x54
#define NV_MMU_PTE_KIND_Z24S8_MS16_2CZ                        0x55
#define NV_MMU_PTE_KIND_Z24S8_4CSZV                           0x56
#define NV_MMU_PTE_KIND_Z24S8_MS2_4CSZV                       0x57
#define NV_MMU_PTE_KIND_Z24S8_MS4_4CSZV                       0x58
#define NV_MMU_PTE_KIND_Z24S8_MS8_4CSZV                       0x59
#define NV_MMU_PTE_KIND_Z24S8_MS16_4CSZV                      0x5a
#define NV_MMU_PTE_KIND_Z24V8_MS4_VC12                        0x5b
#define NV_MMU_PTE_KIND_Z24V8_MS4_VC4                         0x5c
#define NV_MMU_PTE_KIND_Z24V8_MS8_VC8                         0x5d
#define NV_MMU_PTE_KIND_Z24V8_MS8_VC24                        0x5e
#define NV_MMU_PTE_KIND_Z24V8_MS4_VC12_1ZV                    0x63
#define NV_MMU_PTE_KIND_Z24V8_MS4_VC4_1ZV                     0x64
#define NV_MMU_PTE_KIND_Z24V8_MS8_VC8_1ZV                     0x65
#define NV_MMU_PTE_KIND_Z24V8_MS8_VC24_1ZV                    0x66
#define NV_MMU_PTE_KIND_Z24V8_MS4_VC12_2CS                    0x67
#define NV_MMU_PTE_KIND_Z24V8_MS4_VC4_2CS                     0x68
#define NV_MMU_PTE_KIND_Z24V8_MS8_VC8_2CS                     0x69
#define NV_MMU_PTE_KIND_Z24V8_MS8_VC24_2CS                    0x6a
#define NV_MMU_PTE_KIND_Z24V8_MS4_VC12_2CZV                   0x6f
#define NV_MMU_PTE_KIND_Z24V8_MS4_VC4_2CZV                    0x70
#define NV_MMU_PTE_KIND_Z24V8_MS8_VC8_2CZV                    0x71
#define NV_MMU_PTE_KIND_Z24V8_MS8_VC24_2CZV                   0x72
#define NV_MMU_PTE_KIND_Z24V8_MS4_VC12_2ZV                    0x73
#define NV_MMU_PTE_KIND_Z24V8_MS4_VC4_2ZV                     0x74
#define NV_MMU_PTE_KIND_Z24V8_MS8_VC8_2ZV                     0x75
#define NV_MMU_PTE_KIND_Z24V8_MS8_VC24_2ZV                    0x76
#define NV_MMU_PTE_KIND_Z24V8_MS4_VC12_4CSZV                  0x77
#define NV_MMU_PTE_KIND_Z24V8_MS4_VC4_4CSZV                   0x78
#define NV_MMU_PTE_KIND_Z24V8_MS8_VC8_4CSZV                   0x79
#define NV_MMU_PTE_KIND_Z24V8_MS8_VC24_4CSZV                  0x7a
#define NV_MMU_PTE_KIND_ZF32                                  0x7b
#define NV_MMU_PTE_KIND_ZF32_1Z                               0x7c
#define NV_MMU_PTE_KIND_ZF32_MS2_1Z                           0x7d
#define NV_MMU_PTE_KIND_ZF32_MS4_1Z                           0x7e
#define NV_MMU_PTE_KIND_ZF32_MS8_1Z                           0x7f
#define NV_MMU_PTE_KIND_ZF32_MS16_1Z                          0x80
#define NV_MMU_PTE_KIND_ZF32_2CS                              0x81
#define NV_MMU_PTE_KIND_ZF32_MS2_2CS                          0x82
#define NV_MMU_PTE_KIND_ZF32_MS4_2CS                          0x83
#define NV_MMU_PTE_KIND_ZF32_MS8_2CS                          0x84
#define NV_MMU_PTE_KIND_ZF32_MS16_2CS                         0x85
#define NV_MMU_PTE_KIND_ZF32_2CZ                              0x86
#define NV_MMU_PTE_KIND_ZF32_MS2_2CZ                          0x87
#define NV_MMU_PTE_KIND_ZF32_MS4_2CZ                          0x88
#define NV_MMU_PTE_KIND_ZF32_MS8_2CZ                          0x89
#define NV_MMU_PTE_KIND_ZF32_MS16_2CZ                         0x8a
#define NV_MMU_PTE_KIND_X8Z24_X16V8S8_MS4_VC12                0x8b
#define NV_MMU_PTE_KIND_X8Z24_X16V8S8_MS4_VC4                 0x8c
#define NV_MMU_PTE_KIND_X8Z24_X16V8S8_MS8_VC8                 0x8d
#define NV_MMU_PTE_KIND_X8Z24_X16V8S8_MS8_VC24                0x8e
#define NV_MMU_PTE_KIND_X8Z24_X16V8S8_MS4_VC12_1CS            0x8f
#define NV_MMU_PTE_KIND_X8Z24_X16V8S8_MS4_VC4_1CS             0x90
#define NV_MMU_PTE_KIND_X8Z24_X16V8S8_MS8_VC8_1CS             0x91
#define NV_MMU_PTE_KIND_X8Z24_X16V8S8_MS8_VC24_1CS            0x92
#define NV_MMU_PTE_KIND_X8Z24_X16V8S8_MS4_VC12_1ZV            0x97
#define NV_MMU_PTE_KIND_X8Z24_X16V8S8_MS4_VC4_1ZV             0x98
#define NV_MMU_PTE_KIND_X8Z24_X16V8S8_MS8_VC8_1ZV             0x99
#define NV_MMU_PTE_KIND_X8Z24_X16V8S8_MS8_VC24_1ZV            0x9a
#define NV_MMU_PTE_KIND_X8Z24_X16V8S8_MS4_VC12_1CZV           0x9b
#define NV_MMU_PTE_KIND_X8Z24_X16V8S8_MS4_VC4_1CZV            0x9c
#define NV_MMU_PTE_KIND_X8Z24_X16V8S8_MS8_VC8_1CZV            0x9d
#define NV_MMU_PTE_KIND_X8Z24_X16V8S8_MS8_VC24_1CZV           0x9e
#define NV_MMU_PTE_KIND_X8Z24_X16V8S8_MS4_VC12_2CS            0x9f
#define NV_MMU_PTE_KIND_X8Z24_X16V8S8_MS4_VC4_2CS             0xa0
#define NV_MMU_PTE_KIND_X8Z24_X16V8S8_MS8_VC8_2CS             0xa1
#define NV_MMU_PTE_KIND_X8Z24_X16V8S8_MS8_VC24_2CS            0xa2
#define NV_MMU_PTE_KIND_X8Z24_X16V8S8_MS4_VC12_2CSZV          0xa3
#define NV_MMU_PTE_KIND_X8Z24_X16V8S8_MS4_VC4_2CSZV           0xa4
#define NV_MMU_PTE_KIND_X8Z24_X16V8S8_MS8_VC8_2CSZV           0xa5
#define NV_MMU_PTE_KIND_X8Z24_X16V8S8_MS8_VC24_2CSZV          0xa6
#define NV_MMU_PTE_KIND_ZF32_X16V8S8_MS4_VC12                 0xa7
#define NV_MMU_PTE_KIND_ZF32_X16V8S8_MS4_VC4                  0xa8
#define NV_MMU_PTE_KIND_ZF32_X16V8S8_MS8_VC8                  0xa9
#define NV_MMU_PTE_KIND_ZF32_X16V8S8_MS8_VC24                 0xaa
#define NV_MMU_PTE_KIND_ZF32_X16V8S8_MS4_VC12_1CS             0xab
#define NV_MMU_PTE_KIND_ZF32_X16V8S8_MS4_VC4_1CS              0xac
#define NV_MMU_PTE_KIND_ZF32_X16V8S8_MS8_VC8_1CS              0xad
#define NV_MMU_PTE_KIND_ZF32_X16V8S8_MS8_VC24_1CS             0xae
#define NV_MMU_PTE_KIND_ZF32_X16V8S8_MS4_VC12_1ZV             0xb3
#define NV_MMU_PTE_KIND_ZF32_X16V8S8_MS4_VC4_1ZV              0xb4
#define NV_MMU_PTE_KIND_ZF32_X16V8S8_MS8_VC8_1ZV              0xb5
#define NV_MMU_PTE_KIND_ZF32_X16V8S8_MS8_VC24_1ZV             0xb6
#define NV_MMU_PTE_KIND_ZF32_X16V8S8_MS4_VC12_1CZV            0xb7
#define NV_MMU_PTE_KIND_ZF32_X16V8S8_MS4_VC4_1CZV             0xb8
#define NV_MMU_PTE_KIND_ZF32_X16V8S8_MS8_VC8_1CZV             0xb9
#define NV_MMU_PTE_KIND_ZF32_X16V8S8_MS8_VC24_1CZV            0xba
#define NV_MMU_PTE_KIND_ZF32_X16V8S8_MS4_VC12_2CS             0xbb
#define NV_MMU_PTE_KIND_ZF32_X16V8S8_MS4_VC4_2CS              0xbc
#define NV_MMU_PTE_KIND_ZF32_X16V8S8_MS8_VC8_2CS              0xbd
#define NV_MMU_PTE_KIND_ZF32_X16V8S8_MS8_VC24_2CS             0xbe
#define NV_MMU_PTE_KIND_ZF32_X16V8S8_MS4_VC12_2CSZV           0xbf
#define NV_MMU_PTE_KIND_ZF32_X16V8S8_MS4_VC4_2CSZV            0xc0
#define NV_MMU_PTE_KIND_ZF32_X16V8S8_MS8_VC8_2CSZV            0xc1
#define NV_MMU_PTE_KIND_ZF32_X16V8S8_MS8_VC24_2CSZV           0xc2
#define NV_MMU_PTE_KIND_ZF32_X24S8                            0xc3
#define NV_MMU_PTE_KIND_ZF32_X24S8_1CS                        0xc4
#define NV_MMU_PTE_KIND_ZF32_X24S8_MS2_1CS                    0xc5
#define NV_MMU_PTE_KIND_ZF32_X24S8_MS4_1CS                    0xc6
#define NV_MMU_PTE_KIND_ZF32_X24S8_MS8_1CS                    0xc7
#define NV_MMU_PTE_KIND_ZF32_X24S8_MS16_1CS                   0xc8
#define NV_MMU_PTE_KIND_ZF32_X24S8_2CSZV                      0xce
#define NV_MMU_PTE_KIND_ZF32_X24S8_MS2_2CSZV                  0xcf
#define NV_MMU_PTE_KIND_ZF32_X24S8_MS4_2CSZV                  0xd0
#define NV_MMU_PTE_KIND_ZF32_X24S8_MS8_2CSZV                  0xd1
#define NV_MMU_PTE_KIND_ZF32_X24S8_MS16_2CSZV                 0xd2
#define NV_MMU_PTE_KIND_ZF32_X24S8_2CS                        0xd3
#define NV_MMU_PTE_KIND_ZF32_X24S8_MS2_2CS                    0xd4
#define NV_MMU_PTE_KIND_ZF32_X24S8_MS4_2CS                    0xd5
#define NV_MMU_PTE_KIND_ZF32_X24S8_MS8_2CS                    0xd6
#define NV_MMU_PTE_KIND_ZF32_X24S8_MS16_2CS                   0xd7
#define NV_MMU_PTE_KIND_GENERIC_16BX2                         0xfe
#define NV_MMU_PTE_KIND_C32_2C                                0xd8
#define NV_MMU_PTE_KIND_C32_2CBR                              0xd9
#define NV_MMU_PTE_KIND_C32_2CBA                              0xda
#define NV_MMU_PTE_KIND_C32_2CRA                              0xdb
#define NV_MMU_PTE_KIND_C32_2BRA                              0xdc
#define NV_MMU_PTE_KIND_C32_MS2_2C                            0xdd
#define NV_MMU_PTE_KIND_C32_MS2_2CBR                          0xde
#define NV_MMU_PTE_KIND_C32_MS2_2CRA                          0xcc
#define NV_MMU_PTE_KIND_C32_MS4_2C                            0xdf
#define NV_MMU_PTE_KIND_C32_MS4_2CBR                          0xe0
#define NV_MMU_PTE_KIND_C32_MS4_2CBA                          0xe1
#define NV_MMU_PTE_KIND_C32_MS4_2CRA                          0xe2
#define NV_MMU_PTE_KIND_C32_MS4_2BRA                          0xe3
#define NV_MMU_PTE_KIND_C32_MS8_MS16_2C                       0xe4
#define NV_MMU_PTE_KIND_C32_MS8_MS16_2CRA                     0xe5
#define NV_MMU_PTE_KIND_C64_2C                                0xe6
#define NV_MMU_PTE_KIND_C64_2CBR                              0xe7
#define NV_MMU_PTE_KIND_C64_2CBA                              0xe8
#define NV_MMU_PTE_KIND_C64_2CRA                              0xe9
#define NV_MMU_PTE_KIND_C64_2BRA                              0xea
#define NV_MMU_PTE_KIND_C64_MS2_2C                            0xeb
#define NV_MMU_PTE_KIND_C64_MS2_2CBR                          0xec
#define NV_MMU_PTE_KIND_C64_MS2_2CRA                          0xcd
#define NV_MMU_PTE_KIND_C64_MS4_2C                            0xed
#define NV_MMU_PTE_KIND_C64_MS4_2CBR                          0xee
#define NV_MMU_PTE_KIND_C64_MS4_2CBA                          0xef
#define NV_MMU_PTE_KIND_C64_MS4_2CRA                          0xf0
#define NV_MMU_PTE_KIND_C64_MS4_2BRA                          0xf1
#define NV_MMU_PTE_KIND_C64_MS8_MS16_2C                       0xf2
#define NV_MMU_PTE_KIND_C64_MS8_MS16_2CRA                     0xf3
#define NV_MMU_PTE_KIND_C128_2C                               0xf4
#define NV_MMU_PTE_KIND_C128_2CR                              0xf5
#define NV_MMU_PTE_KIND_C128_MS2_2C                           0xf6
#define NV_MMU_PTE_KIND_C128_MS2_2CR                          0xf7
#define NV_MMU_PTE_KIND_C128_MS4_2C                           0xf8
#define NV_MMU_PTE_KIND_C128_MS4_2CR                          0xf9
#define NV_MMU_PTE_KIND_C128_MS8_MS16_2C                      0xfa
#define NV_MMU_PTE_KIND_C128_MS8_MS16_2CR                     0xfb
#define NV_MMU_PTE_KIND_X8C24                                 0xfc
#define NV_MMU_PTE_KIND_PITCH_NO_SWIZZLE                      0xfd

#endif /* __nv_gf106_mmu_hwref_h__ */
