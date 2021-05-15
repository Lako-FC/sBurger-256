<p align="center"> 
  <img align="center" src="https://github.com/0xLaileb/sBurger-256/blob/master/GITHUB_RESOURCES/logo.png?raw=true" width="150"/> 
</p>

<h1><div align="center">sBurger-256</h1>
<p align="center">
  <img src="https://img.shields.io/badge/PRICE-free-%231DC8EE"/>
  <img src="https://img.shields.io/badge/SUPPORT-yes-%231DC8EE"/>
</p>

<p align="center">
  <img src="https://img.shields.io/github/downloads/0xLaileb/sBurger-256/total?color=%231DC8EE&label=DOWNLOADS&logo=GitHub&logoColor=%231DC8EE&style=flat"/>
  <img src="https://img.shields.io/github/last-commit/0xLaileb/sBurger-256?color=%231DC8EE&label=LAST%20COMMIT&style=flat"/>
  <img src="https://img.shields.io/github/release-date/0xLaileb/sBurger-256?color=%231DC8EE&label=RELEASE%20DATE&style=flat"/>
</p>

[releases]: https://github.com/0xLaileb/sBurger-256/releases/

<p align="center">
  <b>Данный класс</b> представляет возможность использовать авторское <a href="https://ru.wikipedia.org/wiki/Симметричные_криптосистемы">симметричное шифрование</a> «sBurger-256».<br>
  <b>Кроме того</b> оно используется в программе «FEncrypt» (шифрование файлов) от организации «Fun-Code»: https://vk.com/official_funcode <br>
  <b>Поддержка</b>: .Net Framework / .Net Core
</p>
<p align="center"> 
  <img align="center" src="https://github.com/0xLaileb/sBurger-256/blob/master/GITHUB_RESOURCES/demo_sburger.png?raw=true"/> 
</p>

## 🔧 Характеристики
- **Создан:** 2020 год
- **Размер ключа:** 256 бит
- **Размер блока:** 8..256 бит
- **Число раундов:** для каждого байта - 1 раунд
- **Тип:** подстановочно-перестановочная сеть

## 🚀 Как использовать

- ### Инициализация класса 
1. Скачайте последний релиз : **[Releases][releases]**.
2. Добавьте файл `sBurger_256.cs` в свой проект.
3. Инициализируйте класс: 
```csharp
sBurger_256 sBurger = new sBurger_256();
```
4. Добавьте ключ (размер должен быть 32 символа (utf8), можете использовать хеш ключа):
```csharp
sBurger.key = Encoding.UTF8.GetBytes("YOURKEY_YOURKEY_YOURKEY_YOURKEY_"); //32 characters
```
**или**
```csharp
byte[] hash = new System.Security.Cryptography.MD5CryptoServiceProvider().ComputeHash(Encoding.UTF8.GetBytes("your key"));
sBurger.key = Encoding.UTF8.GetBytes(BitConverter.ToString(hash).Replace("-", ""));
```
5. Сгенерируйте настройки (1 ключ = 1 раз сгенерировать, повторять не нужно!):
```csharp
sBurger.GenerationSettings();
```
6a. Шифрование блока 256 бит:
```csharp
for (int i = 0; i < all; i++) //1 the passage is 256 bits (32 bytes)
{
    sBurger.Encryption(byte[32]);
}
```
6b. Дешифрование блока 256 бит:
```csharp
for (int i = 0; i < all; i++) //1 the passage is 256 bits (32 bytes)
{
    sBurger.Decryption(byte[32]);
}
```
