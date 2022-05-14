+++
title = "My motivation and some initial thoughts"
date = 2022-05-12
+++

After YEARS of procrastination, I have finally decided to sit down and formally study security.



There are a few motivations for this. First, I always fantasized about doing security when I was at a very young age. This was before I have studied any programming at all. I have to say, it is cool as hell. Even after years, my passion has not diminished. I put it off out of the fear that I would get myself in trouble. The pivoting moment, I believe, is after I have completed UBC's workshop on cybersecurity required for all its employees. Since then, I have become increasingly aware of the URLs I click. I figured that I had to study it to protect myself without being overly cautious. As SunTzu once said, "To know your enemy, you much become your enemy". So, here I am, while on a break, I am studying security. Additionally, studying security opens the path to becoming a DevOps and the path of studying post-quantum cybersecurity which is put on the list of topics that I may consider in the future. Both sound fun and I would happy to work in either field, one for industry and the other for research.



I plan to study the basics in under 20 days.



I initially choose Kali and VirtualBox to be my companions on this journey.  However, I decided to use Kasm instead of VirtualBox upon further search. It incurs a small cost but it also comes with some perks such as automatic privacy and the simplification of management. 

To setup Kasm: follow the tutorial here by NetworkChuck, https://www.youtube.com/watch?v=U7e-mcJdZok&t=444s&ab_channel=NetworkChuck. He did not post the commands in the video description so I will do it here. After loging in, run the following commands to setup the Linux swap partition:
```cmd
root@localhost:~# sudo dd if=/dev/zero bs=1M count=1024 of=/mnt/1GiB.swap
root@localhost:~# sudo chmod 600 /mnt/1GiB.swap
root@localhost:~# sudo mkswap /mnt/1GiB.swap
root@localhost:~# sudo swapon /mnt/1GiB.swap
root@localhost:~# echo '/mnt/1GiB.swap swap swap defaults 0 0' | sudo tee -a /etc/fstab
```

To install Kasm
```cmd
root@localhost:~# wget https://kasm-static-content.s3.amazonaws.com/kasm_release_1.10.0.238225.tar.g
root@localhost:~# tar -xf kasm_release*.tar.gz
root@localhost:~# sudo bash kasm_release/install.sh
```

To download Docker Compose:
```cmd
root@localhost:~# sudo curl -sSL https://get.docker.com/ | sh
```

