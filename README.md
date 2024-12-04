# Sistema de Gestão de Notas de Transporte de Aves

## 📋 Descrição
Sistema web desenvolvido em Flask para gerenciamento completo de notas de transporte de aves, incluindo controle de cargas, gestão financeira e autorizações. O sistema possui diferentes níveis de acesso e permite o acompanhamento detalhado de todo o processo logístico do transporte de aves.

## 🚀 Funcionalidades Principais

### Gestão de Notas
- Criação e edição de notas de transporte
- Registro detalhado de informações sobre:
  - Tipo de ave
  - Quantidade de cargas
  - Dados do transporte (motorista, veículo, km)
  - Informações fiscais (GTA, Nota Fiscal)
  - Controle de peso e quantidade de aves
  - Registro de avarias e quebras
  - Cálculos automáticos de valores

### Controle de Acesso
- Sistema multiusuário com diferentes níveis de permissão:
  - Diretoria
  - Financeiro
  - Usuário
  - Visualizador
- Autenticação segura
- Gestão de usuários (criar, editar, desativar)

### Fluxo de Aprovação
1. Criação da nota
2. Autorização pela diretoria
3. Verificação financeira
4. Aprovação final

### Dashboard e Relatórios
- Visão geral do sistema
- Busca avançada de notas
- Listagem de notas pendentes
- Relatórios financeiros

## 🛠️ Tecnologias Utilizadas
- **Backend**: Python/Flask
- **Banco de Dados**: SQLite
- **ORM**: SQLAlchemy
- **Autenticação**: Flask-Login
- **Frontend**: HTML, CSS, JavaScript
- **Templates**: Jinja2

## 📦 Requisitos do Sistema
- Python 3.7+
- Flask
- Flask-SQLAlchemy
- Flask-Login
- Werkzeug

## 🔧 Instalação e Configuração

1. Clone o repositório
```bash
git clone [URL_DO_REPOSITORIO]
```

2. Instale as dependências
```bash
pip install -r requirements.txt
```

3. Configure as variáveis de ambiente
```bash
SECRET_KEY=your-secret-key-here
```

4. Inicialize o banco de dados
```bash
python
>>> from app import db
>>> with app.app_context():
>>>     db.create_all()
```

5. Inicie o servidor
```bash
python app.py
```

## 🔐 Primeiro Acesso
1. Acesse o sistema através do navegador: `http://localhost:5000`
2. Faça login com as credenciais padrão:
   - Usuário: admin
   - Senha: [senha_fornecida_separadamente]
3. Altere a senha no primeiro acesso

## 📊 Estrutura do Banco de Dados

### Tabela User
- Informações de usuário
- Controle de permissões
- Registro de ações

### Tabela Nota
- Dados completos das notas de transporte
- Campos de autorização e aprovação
- Cálculos e métricas

## 🔍 Funcionalidades Detalhadas

### Gestão de Notas
- Criação de novas notas com numeração automática
- Edição de notas existentes
- Visualização detalhada
- Exclusão de notas (com restrições)
- Busca avançada

### Controle Financeiro
- Registro de valores de frete
- Cálculo automático de valores por km
- Controle de pedágios e despesas
- Aprovação financeira em duas etapas

### Monitoramento
- Dashboard com métricas principais
- Acompanhamento de status das notas
- Relatórios de desempenho
- Histórico de alterações

## 🤝 Suporte

Para suporte ou dúvidas sobre o sistema, entre em contato com a equipe de desenvolvimento através do email [seu-email@dominio.com]

## 📝 Licença

Este projeto está sob a licença [TIPO_DE_LICENCA]. Veja o arquivo LICENSE.md para mais detalhes.

## 🔄 Versionamento

Utilizamos [SemVer](http://semver.org/) para controle de versão. Para ver as versões disponíveis, acesse as [tags neste repositório](https://github.com/seu-usuario/seu-repositorio/tags).

---
Desenvolvido com ❤️ pela sua equipe
