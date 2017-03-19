Name:           dnsbalancer
Version:        0.1.0
Release:        1%{?dist}
Summary:        Daemon to balance UDP DNS requests over DNS servers

License:        GPLv3
URL:            https://github.com/pfactum/dnsbalancer
Source0:        dnsbalancer-0.1.0.tar.gz

BuildRequires:   gcc cmake make libini_config-devel libbsd-devel ldns-devel libmicrohttpd-devel openssl-devel gperftools-devel libunwind-devel
Requires:        libini_config libbsd ldns libmicrohttpd openssl gperftools-devel libunwind
Requires(post):  systemd-units
Requires(preun): systemd-units

%description
Daemon to balance UDP DNS requests over DNS servers

%prep
%setup -q

%build
mkdir build
cd build
cmake -DCMAKE_INSTALL_PREFIX=%{buildroot}%{_prefix} ..
make %{?_smp_mflags}

%install
rm -rf %{buildroot}
%{__install} -D -m0644 configs/%{name}.conf.sample %{buildroot}%{_sysconfdir}/%{name}/%{name}.conf.sample
%{__install} -D -m0644 configs/%{name}.service %{buildroot}%{_unitdir}/%{name}.service
cd build
make install

%clean
rm -rf %{buildroot}

%post
%systemd_post %{name}.service

%preun
%systemd_preun %{name}.service

%files
%defattr(0644, root, root, 0755)
%doc COPYING README.md
%attr(0755, root, root) %{_bindir}/%{name}
%{_sysconfdir}/%{name}/%{name}.conf.sample
%{_unitdir}/%{name}.service

%changelog
