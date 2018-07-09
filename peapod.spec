Summary: EAPOL Proxy Daemon
Name: peapod
Version: 0.1.0
Release: 1
License: GPLv3+
Group: System Environment/Daemons
URL: http://github.com/kangtastic/%{name}
Source0: %{url}/archive/%{name}-%{version}.tar.gz

BuildRequires: gcc
BuildRequires: make
BuildRequires: bison
BuildRequires: flex
BuildRequires: pkgconfig
BuildRequires: systemd
%{?systemd_requires}

%global _hardened_build 1

%description
peapod is a daemon that proxies IEEE 802.1X Extensible Authentication
Protocol over LAN (EAPOL) packets between Ethernet interfaces.

It supports a few tricks on a per-interface basis, so it may be
considered a (highly) rudimentary general-purpose transparent
bridging firewall/rewriting proxy for EAPOL.


%prep
%setup -q

%build
CFLAGS="$RPM_OPT_FLAGS -fPIC -pie -Wl,-z,relro -Wl,-z,now"
export CFLAGS
make %{?_smp_mflags} 

%install
make DESTDIR=%{buildroot} install
# rpmlint: resolve "doc-file-dependency"
chmod -x %{buildroot}%{_datadir}/%{name}/examples/*.sh
# add dummy config file
mkdir -p %{buildroot}%{_sysconfdir}
echo "# Dummy config file for peapod - EAPOL Proxy Daemon" >> %{buildroot}%{_sysconfdir}/%{name}.conf
echo "" >> %{buildroot}%{_sysconfdir}/%{name}.conf
echo "# iface eth0;" >> %{buildroot}%{_sysconfdir}/%{name}.conf
echo "# iface eth1;" >> %{buildroot}%{_sysconfdir}/%{name}.conf

%postun
%systemd_postun %{name}.service

%post
%systemd_post %{name}.service

%preun
%systemd_preun %{name}.service

%files
%license LICENSE
%doc %{_datadir}/%{name}/*.html
%doc %{_datadir}/%{name}/*/*
%config(noreplace) %{_sysconfdir}/peapod.conf
%{_unitdir}/%{name}.service
%{_mandir}/*/*
%{_sbindir}/%{name}

%changelog
* Sun Jul 8 2018 James Seo <kangscinate@gmail.com> - 0.1.0-1
- Initial release
