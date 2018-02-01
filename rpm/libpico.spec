Name:           libpico
Version:        0.0.3
Release:        1%{?dist}
Summary:        Pico support library

License:        Pico Copyright 2017
URL:            https://mypico.org
Source0:        https://gitlab.dtg.cl.cam.ac.uk/pico/%{name}-%{version}-Source.tar.gz

BuildRequires:  gcc
BuildRequires:  autoconf
BuildRequires:  libtool
BuildRequires:  libcurl-devel
BuildRequires:  qrencode-devel
BuildRequires:  openssl-devel
BuildRequires:  check
BuildRequires:  check-devel
BuildRequires:  libpicobt-devel
BuildRequires:  bluez5-libs-devel
Requires:       libpicobt
Requires:       qrencode
Requires:       libcurl
Requires:       openssl-libs
Requires:       bluez5-libs

%description
Provides functionality useful for creating Pico applications. Both client 
 and server-side support are provided.


%package        devel
Summary:        Development files for %{name}
Requires:       %{name}%{?_isa} = %{version}-%{release}

%description    devel
The %{name}-devel package contains libraries and header files for
developing applications that use %{name}.


%prep
%setup -q

%build
%configure
make %{?_smp_mflags}


%install
rm -rf $RPM_ROOT
%make_install
find $RPM_BUILD_ROOT -name '*.la' -exec rm -f {} ';'
find $RPM_BUILD_ROOT -name '*.a' -exec rm -f {} ';'

%check
ctest -V %{?_smp_mflags}

%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig


%files
#%license COPYING
#%doc AUTHORS ChangeLog INSTALL NEWS README
#/usr/lib/*.so.*
%doc /usr/share/doc/pico/AUTHORS
%doc /usr/share/doc/pico/COPYING
%doc /usr/share/doc/pico/ChangeLog
%doc /usr/share/doc/pico/INSTALL
%doc /usr/share/doc/pico/NEWS
%doc /usr/share/doc/pico/README
%{_libdir}/*.so.*
%{_libdir}/*.so

%files devel
#%license COPYING
#%doc AUTHORS ChangeLog INSTALL NEWS README
#%doc add-devel-docs-here
%doc /usr/share/doc/pico/AUTHORS
%doc /usr/share/doc/pico/COPYING
%doc /usr/share/doc/pico/ChangeLog
%doc /usr/share/doc/pico/INSTALL
%doc /usr/share/doc/pico/NEWS
%doc /usr/share/doc/pico/README
%{_includedir}/*
%{_libdir}/*.so
%{_libdir}/*.so.*
%{_libdir}/**.so
#%{_libdir}/**.a
%{_libdir}/pkgconfig/*.pc


%changelog
* Fri Jan 19 2018 David Llewellyn-Jones - 0.0.3-1
 - New state machines to replace blocking sigmaprover/verifier.
 - Improved documentation.
 - JSON parser now supports integers and escape sequences.
 - New example code included.
 - Improved configuration of timeout intervals.
 - Improved logging configuration.
 - Support comments in users.txt.
 - Bluetooth is now an optional build dependency.

* Tue Jul 11 2017 David Llewellyn-Jones - 0.0.2-1
- Add QR code bitmap mode, included double size.
- Add user timeout mechansim to prevent hanging on suspend.
- Impoved unit test coverage.
- Provide abstract channel implementation.
- Bluetooth channel support.
- Added libpicobt as a dependency.
- Improved Windows support.
- Improved C# interface.
- Add support for continuous authentication.
- Provide spec file for RPM support.
- Support Mer and Fedora.
- Changed elliptic curve to prime256v1.
- Ensure code is endian-agnostic.
- Support for client-side Pico communication.
- Switch to using Visual Studio 2015 and .Net 4.6.1.
- Improved documentation.
- Improved (and less verbose) logging.
- New feedback/progress interface.
- Static analysis using cpp-check added to build process.
- Remove dependency on pico-remove.

* Mon Feb  6 2017 David Llewellyn-Jones - 0.0.1-1
- Support multiple connection cycles.

