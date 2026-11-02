# Skill Scout

**Diga o que você precisa, ou não diga nada. O Skill Scout analisa o seu projeto, encontra as melhores skills para o Claude Code, verifica a segurança de cada uma e instala as que você aprovar.**

Já existem dezenas de milhares de skills públicas, e auditorias do setor encontraram problemas críticos em uma parcela relevante delas. Achar a skill certa dá trabalho, e confiar em uma desconhecida é arriscado. O Skill Scout cuida das duas coisas. Você só decide.

```
> /skill-scout:scout quero melhorar a segurança, principalmente a autenticação

  Seu projeto: Next.js + Prisma + Stripe
  Lacunas: .env fora do .gitignore, sem análise de segurança, sem testes, sem CI

  | Skill                        | Resolve              | Segurança                  |
  | security-review              | Revisão OWASP        | 1 ponto para você decidir  |
  | auth-implementation-patterns | Login e permissões   | Nada encontrado            |

  Eu instalaria a security-review primeiro. Quer que eu instale as duas?
```

## Instalação

**Requisitos:** Claude Code e Node.js 20 ou mais recente. O GitHub CLI (`gh auth login`) é opcional, mas recomendado: sem ele a busca de código no GitHub fica desativada e o limite é de 60 chamadas por hora.

```
/plugin marketplace add <seu-usuario>/skill-scout
/plugin install skill-scout@skill-scout
```

Para testar a partir de uma cópia local, sem publicar:

```bash
claude --plugin-dir /caminho/para/skill-scout
```

## Como usar

| Você quer | Comando |
|---|---|
| Análise completa do projeto | `/skill-scout:scout` |
| Algo específico | `/skill-scout:scout preciso de ajuda com testes` |
| Verificar, atualizar ou remover skills instaladas | `/skill-scout:manage` |
| Auditar uma skill que você já tem | `/skill-scout:manage audit .claude/skills/minha-skill` |

Você também pode só pedir em português: "que skills estão faltando neste projeto?". Depois é só conversar: pedir comparações, outras opções ou outro rumo para a busca.

## O que acontece

1. **Analisa o projeto localmente.** Identifica a stack e o que falta em segurança, testes, qualidade de código, DevOps, documentação, dados, frontend e inovação.
2. **Busca em cinco fontes:** `anthropics/skills`, o diretório oficial de plugins, skills.sh, claude-plugins.dev e a busca de código do GitHub.
3. **Compara com critério.** Uma skill popular para uma tecnologia que você não usa fica atrás de uma menos conhecida que serve para o seu caso.
4. **Coloca as finalistas em quarentena** em um commit fixo, como arquivos que não são executados.
5. **Verifica duas vezes:** um scanner de padrões e um auditor de IA que compara o que a skill diz fazer com o que ela faz.
6. **Recomenda e explica** em linguagem simples, inclusive o que rejeitou e por quê.
7. **Instala só o que você aprovar**, com a versão fixada e registrada.

## Segurança

| Situação | O que acontece |
|---|---|
| Achado crítico ou auditoria "maliciosa" | O Skill Scout se recusa a instalar. Não existe opção para forçar. |
| Achado alto ou auditoria "suspeita" | Você recebe a explicação e precisa aceitar cada ponto. |
| Achado médio | Você é avisado. |
| Arquivos alterados depois da análise | A instalação é recusada, e é preciso analisar de novo. |
| Atualização disponível | A nova versão passa por toda a verificação outra vez. |

**O que isso não garante:** nenhuma ferramenta prova que uma skill é segura, e por isso o Skill Scout nunca usa essa palavra. Ele diz o que verificou e o que encontrou. Leia os limites em [SECURITY.md](SECURITY.md).

**Privacidade:** a análise roda na sua máquina. Só termos técnicos genéricos saem para os registros públicos, nunca código, nomes de projeto ou segredos. O conteúdo de arquivos `.env` nunca é aberto.

## Custo

As buscas e o scanner não usam IA. Cada auditoria roda no modelo Sonnet. Nos nossos testes, uma execução completa com 3 auditorias custou entre US$ 0,86 e US$ 1,09, com o agente principal no Opus. O valor muda conforme o modelo da sua sessão, o tamanho das skills e o quanto você conversa.

## Desenvolvimento

```bash
npm test                        # testes, sem dependências nem rede
node scripts/scout.mjs doctor   # verifica Node, GitHub e registros
claude plugin validate . --strict
```

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md): como funciona e por quê
- [docs/ROADMAP.md](docs/ROADMAP.md): próximos passos
- [SECURITY.md](SECURITY.md): modelo de ameaças e limites

## Licença

MIT
