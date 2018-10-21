/*
 * Bareflank Extended APIs
 * Copyright (C) 2018 Assured Information Security, Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef BFZYDIS_H
#define BYZYDIS_H

#include <Zydis/Zydis.h>

inline ZydisDecoder g_decoder;
inline ZydisDecodedInstruction g_insn;

inline void zydis_init()
{
    ZydisDecoderInit(
        &g_decoder,
        ZYDIS_MACHINE_MODE_LONG_64,
        ZYDIS_ADDRESS_WIDTH_64
    );
}

inline ZyanStatus zydis_decode(const void *buf, unsigned long long size)
{
    return ZydisDecoderDecodeBuffer(&g_decoder, buf, size, &g_insn);
}

#ifdef __cplusplus
}
#endif
#endif
