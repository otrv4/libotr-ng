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

#ifndef __TEST_FUNCTIONALS_ALL_H__
#define __TEST_FUNCTIONALS_ALL_H__

void functionals_api_add_tests(void);
void functionals_client_add_tests(void);
void functionals_double_ratchet_add_tests(void);
void functionals_prekey_client_add_tests(void);
void functionals_smp_add_tests(void);

#define REGISTER_FUNCTIONALS                                                   \
  do {                                                                         \
    functionals_api_add_tests();                                               \
    functionals_client_add_tests();                                            \
    functionals_double_ratchet_add_tests();                                    \
    functionals_prekey_client_add_tests();                                     \
    functionals_smp_add_tests();                                               \
  } while (0);

#endif // __TEST_FUNCTIONALS_ALL_H__
