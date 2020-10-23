# SANE PYTHON ENVIRONMENT
# Mad respect for pwal.ch
# https://pwal.ch/posts/2019-11-10-sane-python-environment-2020-part-1-isolation/

echo 'Let us set up pyenv & pipx properly'
sudo aptitude install -y make build-essential libssl-dev zlib1g-dev libbz2-dev libreadline-dev libsqlite3-dev wget curl llvm libncurses5-dev libncursesw5-dev xz-utils tk-dev libffi-dev liblzma-dev python-openssl git
curl -L https://github.com/pyenv/pyenv-installer/raw/master/bin/pyenv-installer | bash

echo 'export PATH="$HOME/.pyenv/bin:$PATH"
eval "$(pyenv init -)"
eval "$(pyenv virtualenv-init -)"' >> ~/.bash_aliases

echo 'NOTE! - Run source ~/.bash_aliases afterwards, & run second part of this script'

# Installing Python 3.7 as AutoRecon & other tools depend on that version.
#pyenv doctor
#pyenv install 3.7.9 && pyenv rehash && pyenv global 3.7.9

# Installing pip because, hello that's muy importante.
#python3 -m pip install pipx && python3 -m pipx ensurepath
