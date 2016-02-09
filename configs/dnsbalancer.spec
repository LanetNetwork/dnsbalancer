Name:           dnsbalancer
Version:        0.0.1
Release:        1%{?dist}
Summary:        Daemon to balance UDP DNS requests over DNS servers

License:        GPLv3
URL:            https://github.com/LanetNetwork/dnsbalancer
Source0:        dnsbalancer-0.0.1.tar.xz
Source1:        dnsbalancer.service

BuildRequires:  gcc cmake make libbsd-devel ldns-devel iniparser-devel libmicrohttpd-devel openssl-devel
Requires:       libbsd ldns iniparser libmicrohttpd openssl

%description
Daemon to balance UDP DNS requests over DNS servers

%prep
%setup -q

%build
mkdir build
cd build
cmake -DCMAKE_INSTALL_PREFIX=%{buildroot}/usr ..
make %{?_smp_mflags}

%install
rm -rf %{buildroot}
%{__mkdir_p} %{buildroot}/etc/%{name}
%{__mkdir_p} %{buildroot}/usr/lib/systemd/system/
%{__install} -m0644 %{name}.conf.sample %{buildroot}/etc/%{name}
%{__install} -m0644 %{SOURCE1} %{buildroot}/usr/lib/systemd/system/%{name}.service
cd build
make install

%files
%doc COPYING README.md
/usr/bin/%{name}
/etc/%{name}/%{name}.conf.sample
/usr/lib/systemd/system/%{name}.service

%changelog
