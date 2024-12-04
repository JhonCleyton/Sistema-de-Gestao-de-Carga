from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///aves.db'
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # 'diretoria', 'financeiro', 'usuario', 'visualizador'
    nome_completo = db.Column(db.String(100))
    email = db.Column(db.String(120))
    data_criacao = db.Column(db.DateTime, default=datetime.now)
    ativo = db.Column(db.Boolean, default=True)
    criado_por_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
        
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
        
    @property
    def is_diretoria(self):
        return self.role == 'diretoria'
        
    @property
    def is_financeiro(self):
        return self.role == 'financeiro'
        
    @property
    def is_visualizador(self):
        return self.role == 'visualizador'
        
    @property
    def can_edit_notes(self):
        return self.role == 'usuario'

class Nota(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    numero = db.Column(db.Integer, unique=True, nullable=False)
    tipo_ave = db.Column(db.String(50), nullable=True)
    num_cargas = db.Column(db.Integer, nullable=True)
    ordem_carga = db.Column(db.String(10), nullable=True)
    data_abate = db.Column(db.DateTime, nullable=True)
    dia_semana = db.Column(db.String(20), nullable=True)
    motorista = db.Column(db.String(100), nullable=True)
    transportadora = db.Column(db.String(100), nullable=True)
    placa_veiculo = db.Column(db.String(20), nullable=True)
    qtd_caixas = db.Column(db.Integer, nullable=True)
    frete_status = db.Column(db.String(20), nullable=True)
    km_saida = db.Column(db.Float, nullable=True)
    km_chegada = db.Column(db.Float, nullable=True)
    valor_frete = db.Column(db.Float, nullable=True)
    pedagios = db.Column(db.Float, nullable=True)
    outras_despesas = db.Column(db.Float, nullable=True)
    produtor = db.Column(db.String(100), nullable=True)
    estado = db.Column(db.String(2), nullable=True)
    nota_fiscal = db.Column(db.String(50), nullable=True)
    data_nf = db.Column(db.DateTime, nullable=True)
    gta = db.Column(db.String(50), nullable=True)
    data_gta = db.Column(db.DateTime, nullable=True)
    aves_granja = db.Column(db.Integer, nullable=True)
    aves_mortas = db.Column(db.Integer, nullable=True)
    aves_recebidas = db.Column(db.Integer, nullable=True)
    aves_contador = db.Column(db.Integer, nullable=True)
    agenciador = db.Column(db.String(100), nullable=True)
    caixas_vazias = db.Column(db.Integer, default=0)
    peso_granja = db.Column(db.Float, nullable=True)
    peso_frigorifico = db.Column(db.Float, nullable=True)
    mortalidade_excesso = db.Column(db.Float, default=0)
    aves_molhadas_granja = db.Column(db.Float, default=0)
    aves_molhadas_chuva = db.Column(db.Float, default=0)
    quebra_maus_tratos = db.Column(db.Float, default=0)
    aves_papo_cheio = db.Column(db.Float, default=0)
    outras_quebras = db.Column(db.Float, default=0)
    descricao_quebras = db.Column(db.String(200))
    adiantamento_frete = db.Column(db.Float, default=0)
    valor_combustivel = db.Column(db.Float, default=0)
    valor_kg = db.Column(db.Float, nullable=True)
    status = db.Column(db.String(20), default='incompleta')
    campos_pendentes = db.Column(db.String(200), nullable=True)
    data_criacao = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Campos de autorização da diretoria
    autorizado_por = db.Column(db.Integer, db.ForeignKey('user.id'))
    autorizado_por_usuario = db.relationship('User', foreign_keys=[autorizado_por])
    autorizada = db.Column(db.Boolean, default=False)
    data_autorizacao = db.Column(db.DateTime)
    assinatura_autorizador = db.Column(db.String(100))
    
    # Campos de aprovação financeira
    verificado_por = db.Column(db.Integer, db.ForeignKey('user.id'))
    verificado_por_usuario = db.relationship('User', foreign_keys=[verificado_por])
    verificado_financeiro = db.Column(db.Boolean, default=False)
    aprovado_financeiro = db.Column(db.Boolean, default=False)
    data_aprovacao_financeiro = db.Column(db.DateTime)
    observacoes_financeiro = db.Column(db.Text)

    @staticmethod
    def proximo_numero():
        ultimo_numero = db.session.query(db.func.max(Nota.numero)).scalar()
        return 1001 if ultimo_numero is None else ultimo_numero + 1

    def calcular_valor_total(self):
        # Peso no frigorífico menos todas as avarias
        peso_liquido = (self.peso_frigorifico or 0) - (
            (self.mortalidade_excesso or 0) +
            (self.aves_molhadas_granja or 0) +
            (self.aves_molhadas_chuva or 0) +
            (self.quebra_maus_tratos or 0) +
            (self.aves_papo_cheio or 0) +
            (self.outras_quebras or 0)
        )
        # Valor total é o peso líquido multiplicado pelo valor por kg
        return peso_liquido * (self.valor_kg or 0) if peso_liquido > 0 else 0

    def calcular_quebra_peso(self):
        # Diferença entre peso na granja e frigorífico
        return self.peso_granja - self.peso_frigorifico

    def calcular_valor_km(self):
        # Valor por km rodado
        km_total = self.km_chegada - self.km_saida
        if km_total > 0:
            return self.valor_frete / km_total
        return 0

    def verificar_completude(self):
        # Lista de campos obrigatórios
        campos_obrigatorios = [
            'numero', 'data_abate', 'tipo_ave', 'motorista',
            'placa_veiculo', 'peso_granja', 'peso_frigorifico',
            'valor_kg', 'valor_frete'
        ]
        
        for campo in campos_obrigatorios:
            valor = getattr(self, campo, None)
            if valor is None or (isinstance(valor, str) and not valor.strip()):
                return False
        return True

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Rotas
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            flash('Login realizado com sucesso!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Usuário ou senha inválidos!', 'danger')
            
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logout realizado com sucesso!', 'success')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    total_notas = Nota.query.count()
    notas_pendentes = Nota.query.filter_by(autorizada=False).count()
    notas_autorizadas = Nota.query.filter_by(autorizada=True).count()
    notas_financeiro = Nota.query.filter_by(autorizada=True, aprovado_financeiro=True).count()
    
    return render_template('dashboard.html',
                         total_notas=total_notas,
                         notas_pendentes=notas_pendentes,
                         notas_autorizadas=notas_autorizadas,
                         notas_financeiro=notas_financeiro)

@app.route('/nova_nota', methods=['GET', 'POST'])
@login_required
def nova_nota():
    if request.method == 'POST':
        # Verificar se algum campo obrigatório está vazio
        campos_obrigatorios = [
            'tipo_ave', 'num_cargas', 'ordem_carga', 'data_abate', 
            'motorista', 'transportadora', 'placa_veiculo', 'qtd_caixas',
            'frete_status', 'km_saida', 'km_chegada', 'valor_frete',
            'pedagios', 'outras_despesas', 'produtor', 'estado',
            'nota_fiscal', 'data_nf', 'gta', 'data_gta',
            'aves_granja', 'aves_mortas', 'aves_recebidas', 'aves_contador',
            'agenciador', 'peso_granja', 'peso_frigorifico', 'valor_kg'
        ]
        
        campos_vazios = []
        for campo in campos_obrigatorios:
            valor = request.form.get(campo, '').strip()
            if not valor:
                campos_vazios.append(campo)

        tem_campo_vazio = len(campos_vazios) > 0

        try:
            # Função auxiliar para converter valores numéricos
            def converter_numero(valor, tipo=float):
                try:
                    valor = valor.strip()
                    return tipo(valor) if valor else 0
                except (ValueError, AttributeError):
                    return 0

            nota = Nota(
                numero=Nota.proximo_numero(),
                tipo_ave=request.form.get('tipo_ave', ''),
                num_cargas=converter_numero(request.form.get('num_cargas', ''), int),
                ordem_carga=request.form.get('ordem_carga', ''),
                data_abate=datetime.strptime(request.form['data_abate'], '%Y-%m-%d') if request.form.get('data_abate') else None,
                dia_semana=datetime.strptime(request.form['data_abate'], '%Y-%m-%d').strftime('%A') if request.form.get('data_abate') else '',
                motorista=request.form.get('motorista', ''),
                transportadora=request.form.get('transportadora', ''),
                placa_veiculo=request.form.get('placa_veiculo', ''),
                qtd_caixas=converter_numero(request.form.get('qtd_caixas', ''), int),
                frete_status=request.form.get('frete_status', ''),
                km_saida=converter_numero(request.form.get('km_saida', '')),
                km_chegada=converter_numero(request.form.get('km_chegada', '')),
                valor_frete=converter_numero(request.form.get('valor_frete', '')),
                pedagios=converter_numero(request.form.get('pedagios', '')),
                outras_despesas=converter_numero(request.form.get('outras_despesas', '')),
                produtor=request.form.get('produtor', ''),
                estado=request.form.get('estado', ''),
                nota_fiscal=request.form.get('nota_fiscal', ''),
                data_nf=datetime.strptime(request.form['data_nf'], '%Y-%m-%d') if request.form.get('data_nf') else None,
                gta=request.form.get('gta', ''),
                data_gta=datetime.strptime(request.form['data_gta'], '%Y-%m-%d') if request.form.get('data_gta') else None,
                aves_granja=converter_numero(request.form.get('aves_granja', ''), int),
                aves_mortas=converter_numero(request.form.get('aves_mortas', ''), int),
                aves_recebidas=converter_numero(request.form.get('aves_recebidas', ''), int),
                aves_contador=converter_numero(request.form.get('aves_contador', ''), int),
                agenciador=request.form.get('agenciador', ''),
                caixas_vazias=converter_numero(request.form.get('caixas_vazias', ''), int),
                peso_granja=converter_numero(request.form.get('peso_granja', '')),
                peso_frigorifico=converter_numero(request.form.get('peso_frigorifico', '')),
                mortalidade_excesso=converter_numero(request.form.get('mortalidade_excesso', '')),
                aves_molhadas_granja=converter_numero(request.form.get('aves_molhadas_granja', '')),
                aves_molhadas_chuva=converter_numero(request.form.get('aves_molhadas_chuva', '')),
                quebra_maus_tratos=converter_numero(request.form.get('quebra_maus_tratos', '')),
                aves_papo_cheio=converter_numero(request.form.get('aves_papo_cheio', '')),
                outras_quebras=converter_numero(request.form.get('outras_quebras', '')),
                descricao_quebras=request.form.get('descricao_quebras', ''),
                adiantamento_frete=converter_numero(request.form.get('adiantamento_frete', '')),
                valor_combustivel=converter_numero(request.form.get('valor_combustivel', '')),
                valor_kg=converter_numero(request.form.get('valor_kg', '')),
                status='incompleta' if tem_campo_vazio else 'completa',
                campos_pendentes=', '.join(campos_vazios) if campos_vazios else None
            )
            
            db.session.add(nota)
            db.session.commit()
            
            if tem_campo_vazio:
                flash('Nota salva como incompleta. Campos pendentes: ' + ', '.join(campos_vazios), 'warning')
            else:
                flash('Nota criada com sucesso!', 'success')
            
            return redirect(url_for('lista_notas'))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Erro ao salvar nota: {str(e)}', 'error')
            return redirect(url_for('nova_nota'))
    
    return render_template('nova_nota.html', novo_numero=Nota.proximo_numero())

@app.route('/ver_nota/<int:id>')
@login_required
def ver_nota(id):
    nota = Nota.query.get_or_404(id)
    return render_template('ver_nota.html', nota=nota)

@app.route('/editar_nota/<int:id>', methods=['GET', 'POST'])
@login_required
def editar_nota(id):
    nota = Nota.query.get_or_404(id)
    
    # Verificar se a nota já foi autorizada ou verificada pelo financeiro
    if nota.autorizada:
        flash('Esta nota não pode ser editada pois já foi autorizada.', 'error')
        return redirect(url_for('ver_nota', id=id))
        
    if nota.verificado_financeiro:
        flash('Esta nota não pode ser editada pois está em verificação financeira.', 'error')
        return redirect(url_for('ver_nota', id=id))
    
    # Verificar se o usuário tem permissão para editar
    if not current_user.can_edit_notes:
        flash('Você não tem permissão para editar notas.', 'error')
        return redirect(url_for('ver_nota', id=id))
        
    if request.method == 'POST':
        try:
            # Verificar novamente se a nota não foi autorizada enquanto o usuário editava
            nota_atual = Nota.query.get_or_404(id)
            if nota_atual.autorizada:
                flash('Esta nota foi autorizada por outro usuário e não pode mais ser editada.', 'error')
                return redirect(url_for('ver_nota', id=id))
                
            if nota_atual.verificado_financeiro:
                flash('Esta nota entrou em verificação financeira e não pode mais ser editada.', 'error')
                return redirect(url_for('ver_nota', id=id))
            
            # Atualizar campos da nota
            nota.tipo_ave = request.form['tipo_ave']
            nota.num_cargas = int(request.form['num_cargas'])
            nota.ordem_carga = request.form['ordem_carga']
            nota.data_abate = datetime.strptime(request.form['data_abate'], '%Y-%m-%d')
            nota.dia_semana = request.form['dia_semana']
            nota.motorista = request.form['motorista']
            nota.transportadora = request.form['transportadora']
            nota.placa_veiculo = request.form['placa_veiculo']
            nota.qtd_caixas = int(request.form.get('qtd_caixas', 0))
            nota.frete_status = request.form['frete_status']
            nota.km_saida = float(request.form.get('km_saida', 0))
            nota.km_chegada = float(request.form.get('km_chegada', 0))
            nota.valor_frete = float(request.form.get('valor_frete', 0))
            nota.pedagios = float(request.form.get('pedagios', 0))
            nota.outras_despesas = float(request.form.get('outras_despesas', 0))
            nota.produtor = request.form['produtor']
            nota.estado = request.form['estado']
            nota.nota_fiscal = request.form['nota_fiscal']
            nota.data_nf = datetime.strptime(request.form['data_nf'], '%Y-%m-%d')
            nota.gta = request.form['gta']
            nota.data_gta = datetime.strptime(request.form['data_gta'], '%Y-%m-%d')
            nota.aves_granja = int(request.form.get('aves_granja', 0))
            nota.aves_mortas = int(request.form.get('aves_mortas', 0))
            nota.aves_recebidas = int(request.form.get('aves_recebidas', 0))
            nota.aves_contador = int(request.form.get('aves_contador', 0))
            nota.agenciador = request.form['agenciador']
            nota.caixas_vazias = int(request.form.get('caixas_vazias', 0))
            nota.peso_granja = float(request.form.get('peso_granja', 0))
            nota.peso_frigorifico = float(request.form.get('peso_frigorifico', 0))
            nota.mortalidade_excesso = float(request.form.get('mortalidade_excesso', 0))
            nota.aves_molhadas_granja = float(request.form.get('aves_molhadas_granja', 0))
            nota.aves_molhadas_chuva = float(request.form.get('aves_molhadas_chuva', 0))
            nota.quebra_maus_tratos = float(request.form.get('quebra_maus_tratos', 0))
            nota.aves_papo_cheio = float(request.form.get('aves_papo_cheio', 0))
            nota.outras_quebras = float(request.form.get('outras_quebras', 0))
            nota.descricao_quebras = request.form.get('descricao_quebras', '')
            nota.valor_kg = float(request.form.get('valor_kg', 0))
            nota.adiantamento_frete = float(request.form.get('adiantamento_frete', 0))
            nota.valor_combustivel = float(request.form.get('valor_combustivel', 0))

            # Verificar campos vazios
            campos_vazios = []
            for campo, valor in request.form.items():
                if not valor and campo != 'csrf_token':
                    campos_vazios.append(campo)
                    
            if campos_vazios:
                nota.campos_pendentes = ','.join(campos_vazios)
                nota.status = 'incompleta'
            else:
                nota.campos_pendentes = None
                nota.status = 'completa'

            db.session.commit()
            flash('Nota atualizada com sucesso!', 'success')
            return redirect(url_for('ver_nota', id=id))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Erro ao atualizar nota: {str(e)}', 'error')
            return redirect(url_for('editar_nota', id=id))
            
    return render_template('editar_nota.html', nota=nota)

@app.route('/autorizar_nota/<int:id>', methods=['GET', 'POST'])
@login_required
def autorizar_nota(id):
    if not current_user.is_diretoria:
        flash('Apenas diretoria pode autorizar notas.', 'error')
        return redirect(url_for('ver_nota', id=id))
        
    nota = Nota.query.get_or_404(id)
    if request.method == 'POST':
        senha = request.form.get('senha')
        assinatura = request.form.get('assinatura')
        user = User.query.get(current_user.id)
        
        if not user.check_password(senha):
            flash('Senha incorreta!', 'danger')
            return redirect(url_for('autorizar_nota', id=id))
            
        nota.autorizada = True
        nota.data_autorizacao = datetime.now()
        nota.autorizado_por = current_user.id
        nota.assinatura_autorizador = assinatura
        flash('Nota autorizada com sucesso!', 'success')
            
        db.session.commit()
        return redirect(url_for('lista_notas'))
        
    return render_template('autorizar_nota.html', nota=nota)

@app.route('/financeiro')
@login_required
def financeiro():
    if not current_user.is_financeiro:
        flash('Acesso negado!', 'danger')
        return redirect(url_for('dashboard'))
        
    # Buscar apenas notas que foram autorizadas pela diretoria
    notas = Nota.query.filter_by(autorizada=True).order_by(Nota.data_autorizacao.desc()).all()
    return render_template('financeiro.html', notas=notas)

@app.route('/aprovar_financeiro/<int:id>', methods=['GET', 'POST'])
@login_required
def aprovar_financeiro(id):
    if not current_user.is_financeiro:
        flash('Acesso negado!', 'danger')
        return redirect(url_for('dashboard'))
        
    nota = Nota.query.get_or_404(id)
    if request.method == 'POST':
        senha = request.form.get('senha')
        observacoes = request.form.get('observacoes')
        user = User.query.get(current_user.id)
        
        if not user.check_password(senha):
            flash('Senha incorreta!', 'danger')
            return redirect(url_for('aprovar_financeiro', id=id))
            
        nota.aprovado_financeiro = True
        nota.data_aprovacao_financeiro = datetime.now()
        nota.verificado_por = current_user.id
        nota.observacoes_financeiro = observacoes
        
        db.session.commit()
        flash('Nota aprovada pelo financeiro com sucesso!', 'success')
        return redirect(url_for('financeiro'))
        
    return render_template('aprovar_financeiro.html', nota=nota)

@app.route('/buscar_notas')
@login_required
def buscar_notas():
    termo = request.args.get('termo', '')
    data_inicio = request.args.get('data_inicio')
    data_fim = request.args.get('data_fim')
    status = request.args.get('status', 'todas')
    
    query = Nota.query
    
    if termo:
        query = query.filter(
            db.or_(
                Nota.produtor.ilike(f'%{termo}%'),
                Nota.motorista.ilike(f'%{termo}%'),
                Nota.transportadora.ilike(f'%{termo}%'),
                Nota.nota_fiscal.ilike(f'%{termo}%'),
                Nota.gta.ilike(f'%{termo}%')
            )
        )
    
    if data_inicio:
        query = query.filter(Nota.data_criacao >= datetime.strptime(data_inicio, '%Y-%m-%d'))
    if data_fim:
        query = query.filter(Nota.data_criacao <= datetime.strptime(data_fim, '%Y-%m-%d') + timedelta(days=1))
        
    if status == 'pendente':
        query = query.filter_by(autorizada=False)
    elif status == 'autorizada':
        query = query.filter_by(autorizada=True)
    elif status == 'financeiro':
        query = query.filter_by(autorizada=True, aprovado_financeiro=False)
    elif status == 'incompleta':
        query = query.filter_by(status='incompleta')
        
    notas = query.order_by(Nota.data_criacao.desc()).all()
    
    return render_template('buscar_notas.html', 
                         notas=notas, 
                         termo=termo,
                         data_inicio=data_inicio,
                         data_fim=data_fim,
                         status=status)

@app.route('/lista_notas')
@login_required
def lista_notas():
    status = request.args.get('status', 'todas')
    query = Nota.query
    
    if status == 'pendente':
        query = query.filter_by(autorizada=False)
    elif status == 'autorizada':
        query = query.filter_by(autorizada=True)
    elif status == 'financeiro':
        query = query.filter_by(autorizada=True, verificado_financeiro=False)
        
    notas = query.order_by(Nota.data_criacao.desc()).all()
    
    return render_template('lista_notas.html', 
                         notas=notas,
                         status=status)

@app.route('/notas_incompletas')
@login_required
def notas_incompletas():
    # Buscar notas que não estão autorizadas nem aprovadas
    notas = Nota.query.filter(
        (Nota.autorizada == False) | 
        (Nota.aprovado_financeiro == False)
    ).order_by(Nota.data_criacao.desc()).all()
    return render_template('notas_incompletas.html', notas=notas)

@app.route('/editar_nota_incompleta/<int:id>', methods=['GET', 'POST'])
@login_required
def editar_nota_incompleta(id):
    nota = Nota.query.get_or_404(id)
    
    if request.method == 'POST':
        # Atualizar campos da nota
        nota.tipo_ave = request.form.get('tipo_ave')
        nota.num_cargas = request.form.get('num_cargas')
        nota.ordem_carga = request.form.get('ordem_carga')
        nota.data_abate = datetime.strptime(request.form.get('data_abate'), '%Y-%m-%d') if request.form.get('data_abate') else None
        nota.dia_semana = request.form.get('dia_semana')
        nota.motorista = request.form.get('motorista')
        nota.transportadora = request.form.get('transportadora')
        nota.placa_veiculo = request.form.get('placa_veiculo')
        nota.qtd_caixas = request.form.get('qtd_caixas')
        nota.frete_status = request.form.get('frete_status')
        nota.km_saida = float(request.form.get('km_saida')) if request.form.get('km_saida') else None
        nota.km_chegada = float(request.form.get('km_chegada')) if request.form.get('km_chegada') else None
        nota.valor_frete = float(request.form.get('valor_frete')) if request.form.get('valor_frete') else None
        nota.pedagios = float(request.form.get('pedagios')) if request.form.get('pedagios') else None
        nota.outras_despesas = float(request.form.get('outras_despesas')) if request.form.get('outras_despesas') else None
        nota.produtor = request.form.get('produtor')
        nota.estado = request.form.get('estado')
        nota.nota_fiscal = request.form.get('nota_fiscal')
        nota.data_nf = datetime.strptime(request.form.get('data_nf'), '%Y-%m-%d') if request.form.get('data_nf') else None
        nota.gta = request.form.get('gta')
        nota.data_gta = datetime.strptime(request.form.get('data_gta'), '%Y-%m-%d') if request.form.get('data_gta') else None
        nota.aves_granja = int(request.form.get('aves_granja')) if request.form.get('aves_granja') else None
        nota.aves_mortas = int(request.form.get('aves_mortas')) if request.form.get('aves_mortas') else None
        nota.aves_recebidas = int(request.form.get('aves_recebidas')) if request.form.get('aves_recebidas') else None
        nota.aves_contador = int(request.form.get('aves_contador')) if request.form.get('aves_contador') else None
        nota.agenciador = request.form.get('agenciador')
        nota.caixas_vazias = int(request.form.get('caixas_vazias')) if request.form.get('caixas_vazias') else 0
        nota.peso_granja = float(request.form.get('peso_granja')) if request.form.get('peso_granja') else None
        nota.peso_frigorifico = float(request.form.get('peso_frigorifico')) if request.form.get('peso_frigorifico') else None
        nota.mortalidade_excesso = float(request.form.get('mortalidade_excesso')) if request.form.get('mortalidade_excesso') else 0
        nota.aves_molhadas_granja = float(request.form.get('aves_molhadas_granja')) if request.form.get('aves_molhadas_granja') else 0
        nota.aves_molhadas_chuva = float(request.form.get('aves_molhadas_chuva')) if request.form.get('aves_molhadas_chuva') else 0
        nota.quebra_maus_tratos = float(request.form.get('quebra_maus_tratos')) if request.form.get('quebra_maus_tratos') else 0
        nota.aves_papo_cheio = float(request.form.get('aves_papo_cheio')) if request.form.get('aves_papo_cheio') else 0
        nota.outras_quebras = float(request.form.get('outras_quebras')) if request.form.get('outras_quebras') else 0
        nota.descricao_quebras = request.form.get('descricao_quebras')
        nota.adiantamento_frete = float(request.form.get('adiantamento_frete')) if request.form.get('adiantamento_frete') else 0
        nota.valor_combustivel = float(request.form.get('valor_combustivel')) if request.form.get('valor_combustivel') else 0
        nota.valor_kg = float(request.form.get('valor_kg')) if request.form.get('valor_kg') else None

        db.session.commit()
        flash('Nota atualizada com sucesso!', 'success')
        return redirect(url_for('notas_incompletas'))
        
    return render_template('editar_nota_incompleta.html', nota=nota)

@app.route('/buscar_nota')
@login_required
def buscar_nota():
    return render_template('buscar_nota.html')

@app.route('/usuarios')
@login_required
def lista_usuarios():
    if not current_user.is_diretoria:
        flash('Acesso negado. Apenas diretoria pode gerenciar usuários.', 'danger')
        return redirect(url_for('dashboard'))
    
    usuarios = User.query.all()
    return render_template('usuarios.html', usuarios=usuarios)

@app.route('/novo_usuario', methods=['GET', 'POST'])
@login_required
def novo_usuario():
    if not current_user.is_diretoria:
        flash('Acesso negado. Apenas diretoria pode criar novos usuários.', 'error')
        return redirect(url_for('lista_usuarios'))
        
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']
        nome_completo = request.form['nome_completo']
        email = request.form['email']
        
        if User.query.filter_by(username=username).first():
            flash('Nome de usuário já existe!', 'error')
            return redirect(url_for('novo_usuario'))
            
        if role not in ['diretoria', 'financeiro', 'usuario', 'visualizador']:
            flash('Tipo de usuário inválido!', 'error')
            return redirect(url_for('novo_usuario'))
            
        user = User(
            username=username,
            role=role,
            nome_completo=nome_completo,
            email=email,
            criado_por_id=current_user.id
        )
        user.set_password(password)
        
        db.session.add(user)
        db.session.commit()
        
        flash('Usuário criado com sucesso!', 'success')
        return redirect(url_for('lista_usuarios'))
        
    return render_template('novo_usuario.html')

@app.route('/editar_usuario/<int:id>', methods=['GET', 'POST'])
@login_required
def editar_usuario(id):
    if not current_user.is_diretoria:
        flash('Acesso negado. Apenas diretoria pode editar usuários.', 'danger')
        return redirect(url_for('dashboard'))
        
    user = User.query.get_or_404(id)
    
    if request.method == 'POST':
        user.username = request.form.get('username')
        user.role = request.form.get('role')
        user.nome_completo = request.form.get('nome_completo')
        user.email = request.form.get('email')
        user.ativo = 'ativo' in request.form
        
        password = request.form.get('password')
        if password:  # Só atualiza senha se foi fornecida
            user.set_password(password)
            
        db.session.commit()
        flash('Usuário atualizado com sucesso!', 'success')
        return redirect(url_for('lista_usuarios'))
        
    return render_template('editar_usuario.html', user=user)

@app.route('/desativar_usuario/<int:id>')
@login_required
def desativar_usuario(id):
    if not current_user.is_diretoria:
        flash('Acesso negado. Apenas diretoria pode desativar usuários.', 'danger')
        return redirect(url_for('dashboard'))
        
    user = User.query.get_or_404(id)
    if user.id == current_user.id:
        flash('Você não pode desativar seu próprio usuário!', 'danger')
        return redirect(url_for('lista_usuarios'))
        
    user.ativo = False
    db.session.commit()
    flash('Usuário desativado com sucesso!', 'success')
    return redirect(url_for('lista_usuarios'))

@app.route('/api/excluir_nota/<int:id>', methods=['DELETE'])
@login_required
def excluir_nota(id):
    try:
        nota = Nota.query.get_or_404(id)
        db.session.delete(nota)
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)})

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        
        # Criar usuário inicial da diretoria se não existir
        if not User.query.filter_by(username='diretoria').first():
            user = User(
                username='diretoria',
                role='diretoria',
                nome_completo='Administrador do Sistema',
                email='admin@empresa.com',
                ativo=True
            )
            user.set_password('diretoria123')
            db.session.add(user)
            db.session.commit()
            
    app.run(host='10.0.1.242', port=5000, debug=True)
