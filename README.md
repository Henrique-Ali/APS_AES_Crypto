# UNIP_APS_SEMESTRE_2
## Descrição
Este projeto foi desenvolvido no 2° semestre da Faculdade UNIP em 2020. O objetivo do trabalho era implementar uma criptografia já conhecida em Python, fazer uma ou mais alterações nela, e garantir que o código pudesse aceitar uma entrada de texto de até 128 caracteres, apresentando o texto codificado e decodificado.

## Desenvolvedores
* [Caio Pereira](https://github.com/Caio-Pereira)
* [Henrique Ali](https://github.com/Henrique-Ali?tab=repositories)
* Rebecca Amaral
* João Stabile
* Tauan Souza
  
## Sobre o Projeto
O projeto implementa o método de criptografia AES (Advanced Encryption Standard) com modificações adicionais:

* **Cifra de César**: Uma alteração no meio do processo de criptografia, adicionando uma camada extra de segurança.
* **Base64**: Codificação final da saída em Base64 para garantir que o texto criptografado possa ser facilmente armazenado e transmitido.
  
## Funcionalidades
* Entrada de Texto: Aceita uma entrada de texto de até 128 caracteres.
* Criptografia: Aplica o método AES, seguido por uma cifra de César, e finalmente codifica o resultado em Base64.
* Decodificação: Reverte o processo para retornar ao texto original.

## Instruções
* Insira um texto de até 128 caracteres.
* O código irá criptografar o texto utilizando AES, aplicar a cifra de César, e codificar o resultado em Base64.
* A decodificação reverterá esses passos para recuperar o texto original.
