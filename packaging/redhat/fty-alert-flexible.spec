#
#    fty-alert-flexible - agent for creating evaluating alerts
#
#    Copyright (C) 2016 - 2017 Tomas Halman
#
#    This program is free software; you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation; either version 2 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License along
#    with this program; if not, write to the Free Software Foundation, Inc.,
#    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#

# To build with draft APIs, use "--with drafts" in rpmbuild for local builds or add
#   Macros:
#   %_with_drafts 1
# at the BOTTOM of the OBS prjconf
%bcond_with drafts
%if %{with drafts}
%define DRAFTS yes
%else
%define DRAFTS no
%endif
%define SYSTEMD_UNIT_DIR %(pkg-config --variable=systemdsystemunitdir systemd)
Name:           fty-alert-flexible
Version:        0.1.0
Release:        1
Summary:        agent for creating evaluating alerts
License:        GPL-2.0+
URL:            https://42ity.org
Source0:        %{name}-%{version}.tar.gz
Group:          System/Libraries
# Note: ghostscript is required by graphviz which is required by
#       asciidoc. On Fedora 24 the ghostscript dependencies cannot
#       be resolved automatically. Thus add working dependency here!
BuildRequires:  ghostscript
BuildRequires:  asciidoc
BuildRequires:  automake
BuildRequires:  autoconf
BuildRequires:  libtool
BuildRequires:  pkgconfig
BuildRequires:  systemd-devel
BuildRequires:  systemd
%{?systemd_requires}
BuildRequires:  xmlto
BuildRequires:  libsodium-devel
BuildRequires:  zeromq-devel
BuildRequires:  czmq-devel
BuildRequires:  malamute-devel
BuildRequires:  fty-proto-devel
BuildRequires:  lua-devel
BuildRoot:      %{_tmppath}/%{name}-%{version}-build

%description
fty-alert-flexible agent for creating evaluating alerts.

%package -n libfty_alert_flexible0
Group:          System/Libraries
Summary:        agent for creating evaluating alerts shared library

%description -n libfty_alert_flexible0
This package contains shared library for fty-alert-flexible: agent for creating evaluating alerts

%post -n libfty_alert_flexible0 -p /sbin/ldconfig
%postun -n libfty_alert_flexible0 -p /sbin/ldconfig

%files -n libfty_alert_flexible0
%defattr(-,root,root)
%{_libdir}/libfty_alert_flexible.so.*

%package devel
Summary:        agent for creating evaluating alerts
Group:          System/Libraries
Requires:       libfty_alert_flexible0 = %{version}
Requires:       libsodium-devel
Requires:       zeromq-devel
Requires:       czmq-devel
Requires:       malamute-devel
Requires:       fty-proto-devel
Requires:       lua-devel

%description devel
agent for creating evaluating alerts development tools
This package contains development files for fty-alert-flexible: agent for creating evaluating alerts

%files devel
%defattr(-,root,root)
%{_includedir}/*
%{_libdir}/libfty_alert_flexible.so
%{_libdir}/pkgconfig/libfty_alert_flexible.pc
%{_mandir}/man3/*
%{_mandir}/man7/*

%prep

%setup -q

%build
sh autogen.sh
%{configure} --enable-drafts=%{DRAFTS} --with-systemd-units
make %{_smp_mflags}

%install
make install DESTDIR=%{buildroot} %{?_smp_mflags}

# remove static libraries
find %{buildroot} -name '*.a' | xargs rm -f
find %{buildroot} -name '*.la' | xargs rm -f

%files
%defattr(-,root,root)
%doc README.md
%{_bindir}/fty-alert-flexible
%{_mandir}/man1/fty-alert-flexible*
%config(noreplace) %{_sysconfdir}/fty-alert-flexible/fty-alert-flexible.cfg
%{SYSTEMD_UNIT_DIR}/fty-alert-flexible.service
%dir %{_sysconfdir}/fty-alert-flexible
%if 0%{?suse_version} > 1315
%post
%systemd_post fty-alert-flexible.service
%preun
%systemd_preun fty-alert-flexible.service
%postun
%systemd_postun_with_restart fty-alert-flexible.service
%endif

%changelog
