/*
 * Copyright (c) 2015 Cossack Labs Limited
 *
 *    This program is free software; you can redistribute it and/or modify
 *    it under the terms of the GNU General Public License as published by
 *    the Free Software Foundation; either version 2 of the License, or
 *    (at your option) any later version.
 *
 *    This program is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    GNU General Public License for more details.
 *
 *    You should have received a copy of the GNU General Public License
 *    along with this program; if not, write to the Free Software
 *    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301 USA
*/

#ifndef SESTO_EXCEPTION_HPP
#define SESTO_EXCEPTION_HPP

#include <stdexcept>

namespace sesto{
	class exception: public std::runtime_error{
	    public:
		explicit exception(const char* what):
		std::runtime_error(what){}
	};

	class buffer_too_small_exception: public themis::exception{
	    public:
		explicit buffer_too_small_exception(const char* what):
		themis::exception(what){}
	};
}//sesto ns