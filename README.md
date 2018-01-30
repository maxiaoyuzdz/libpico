# libpico ReadMe

The Pico project is liberating humanity from passwords. See https://www.mypico.org.

Libpico provides a library for performing Pico pairing and authentication. It has code for both the client and server sides of the Pico protocol.

## Documentation

For more details on the libpico API and how to build the entire Pico stack, see the developer docs.

https://docs.mypico.org/developer/

If you want to build all the Pico components from source in one go, without having to worry about the details, see:

https://github.com/mypico/pico-build-all

## Install from source

You'll need to ensure you've installed the [build dependencies](https://docs.mypico.org/developer/libpico/#deps) before you attempt to compile and install libpico. This includes building and installing libpicobt from the Pico repositories. See the [libpicobt repository](https://github.com/mypico/libpicobt) for instructions for this.

If you're using Ubuntu 16.04, you can install the remaining build dependencies using `apt`.

```
sudo apt install libssl1.0.0 libcurl3 libqrencode3 libbluetooth3 libc6 liburl-dispatcher1 \
  libcurl4-openssl-dev libqrencode-dev libssl-dev libbluetooth-dev git gcc make check \
  pkg-config autotools-dev devscripts debhelper dh-systemd liburl-dispatcher1-dev \
  openssh-client doxygen graphviz dh-exec
```

Assuming you've got all these, download the latest version from the git repository and move inside the project folder.

```
git clone git@github.com:mypico/libpico.git
cd libpico
```

You can now build using autoconf with the following commands:

```
./configure
make
```

After this, the cleanest way to install it is to build the deb or rpm packages and install these:

```
debuild -us -uc -b --lintian-opts -X changes-file
sudo dpkg -i ../libpico1_0.0.2-1_amd64.deb
sudo dpkg -i ../libpico1-dev_0.0.2-1_amd64.deb
```

## License

Libpico is released under the AGPL licence. Read COPYING for information.

## Contributing

We welcome comments and contributions to the project. If you're interested in contributing please see here: https://get.mypico.org/cla/

## Contact and Links

More information can be found at: http://mypico.org

The Pico project team:
 * Frank Stajano (PI), Frank.Stajano@cl.cam.ac.uk
 * David Llewellyn-Jones, David.Llewellyn-Jones@cl.cam.ac.uk
 * Claudio Dettoni, cd611@cl.cam.ac.uk
 * Seb Aebischer, seb.aebischer@cl.cam.ac.uk
 * Kat Krol, kat.krol@cl.cam.ac.uk
 * David Harrison, David.Harrison@cl.cam.ac.uk

