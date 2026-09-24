# Painel Valle — app (PWA no GitHub Pages)

Tela rápida de consulta do painel do Claude, no iPhone, sem nada do Claude em volta. O painel do Claude continua sendo onde se ESCREVE.

## Arquivos
- `index.html` — o app. Pede a senha mestra uma vez, deriva a chave no aparelho, baixa `dados/*.enc` e decifra.
- `configurar.html` — primeira vez: cria a senha mestra e mostra a **chave pública** (`pv1.<sal>.<pub>`) para colar no painel do Claude.
- `cripto.js` — X25519 + PBKDF2 + HKDF + AES-256-GCM, tudo no aparelho.
- `manifest.webmanifest`, `sw.js` — "Adicionar à Tela de Início" e abertura rápida/offline.
- `icones/` — ícone do app (brasão): 180, 192 e 512 px.
- `dados/chave.pub` — a chave pública (colada pelo Alfred). `dados/indice.json` — o que está publicado e quando. `dados/*.enc` — os dados cifrados.
- `espelho/cifrar.py` — o que a rotina usa para cifrar: `python3 espelho/cifrar.py <pasta_json_em_claro> dados`.

## Segurança
A rotina nunca conhece a senha: só a chave pública. O repositório pode ser público — quem achar o endereço vê texto sem sentido. Quem tem a senha entra sem precisar da conta Claude (é o plano de contingência). Se a senha se perder, os dados do app viram lixo; o original continua no painel do Claude e o app se refaz com senha nova.

## Como a rotina publica (tarefa agendada do Alfred)
1. Lê as coleções do painel com ArtifactData (decisoes, fila, recados, atletas, jogos, rotina, acervo, contexto) e grava um JSON por coleção numa pasta temporária.
2. `python3 espelho/cifrar.py <pasta> dados`.
3. `git add dados && git commit -m "espelho <data>" && git push` (token do GitHub com permissão de conteúdo só neste repositório).
4. GitHub Pages publica em segundos.
