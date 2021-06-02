# token-keeper-client

[Token Keeper](https://github.com/rbkmoney/token-keeper) service client library 

## Сборка

Для запуска процесса сборки достаточно выполнить просто:

    make

Чтобы запустить проект в режиме разработки и получить стандартный [Erlang shell][2], нужно всего лишь:

    make shell

## CI/CD
Данная библиотека проходит автоматическую проверку с помощью Github Actions, которую можно также запустить локально с помощью [act](https://github.com/nektos/act):
```
act
```

> _Хозяйке на заметку._ В зависимости от вашего окружения и операционной системы вам может понадобиться [Docker Machine][4].
