/*
 *  This file is part of the Off-the-Record Next Generation Messaging
 *  library (libotr-ng).
 *
 *  Copyright (C) 2016-2019, the libotr-ng contributors.
 *
 *  This library is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as published by
 *  the Free Software Foundation, either version 2.1 of the License, or
 *  (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public License
 *  along with this library.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "prekey_fragment.h"
#include "fragment.h"

#define PREKEY_UNFRAGMENT_FORMAT "?OTRP|%08x|%08x|%08x,%05hu,%05hu,%n%*[^,],%n"

INTERNAL otrng_result otrng_fragment_message_receive(
    char **unfrag_msg, list_element_s **contexts, const char *msg,
    const uint32_t our_instance_tag) {
  return otrng_unfragment_message_generic(unfrag_msg, contexts, msg,
                                          our_instance_tag, "?OTRP|",
                                          PREKEY_UNFRAGMENT_FORMAT);
}
