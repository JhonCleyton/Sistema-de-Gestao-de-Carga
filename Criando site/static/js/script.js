// Função para formatar números como moeda
function formatCurrency(value) {
    return new Intl.NumberFormat('pt-BR', {
        style: 'currency',
        currency: 'BRL'
    }).format(value);
}

// Função para formatar números com 2 casas decimais
function formatNumber(value) {
    return new Intl.NumberFormat('pt-BR', {
        minimumFractionDigits: 2,
        maximumFractionDigits: 2
    }).format(value);
}

// Função para calcular o total do frete
function calcularTotalFrete() {
    const valorFrete = parseFloat(document.querySelector('[name="valor_frete"]').value) || 0;
    const pedagios = parseFloat(document.querySelector('[name="pedagios"]').value) || 0;
    const outrasDespesas = parseFloat(document.querySelector('[name="outras_despesas"]').value) || 0;
    
    const total = valorFrete + pedagios + outrasDespesas;
    document.querySelector('[name="total_frete"]').value = formatNumber(total);
}

// Função para calcular o valor por km
function calcularValorPorKm() {
    const kmTotal = parseFloat(document.querySelector('[name="km_total"]').value) || 0;
    const valorFrete = parseFloat(document.querySelector('[name="valor_frete"]').value) || 0;
    
    if (kmTotal > 0) {
        const valorPorKm = valorFrete / kmTotal;
        document.querySelector('[name="valor_por_km"]').value = formatNumber(valorPorKm);
    }
}

// Função para calcular o peso total a pagar
function calcularPesoTotal() {
    const pesoFrigorifico = parseFloat(document.querySelector('[name="peso_frigorifico"]').value) || 0;
    const mortalidadeExcesso = parseFloat(document.querySelector('[name="mortalidade_excesso"]').value) || 0;
    const avesMolhadasGranja = parseFloat(document.querySelector('[name="aves_molhadas_granja"]').value) || 0;
    const avesMolhadasChuva = parseFloat(document.querySelector('[name="aves_molhadas_chuva"]').value) || 0;
    const quebraMausTratos = parseFloat(document.querySelector('[name="quebra_maus_tratos"]').value) || 0;
    const avesPapoCheio = parseFloat(document.querySelector('[name="aves_papo_cheio"]').value) || 0;
    const outrasQuebras = parseFloat(document.querySelector('[name="outras_quebras"]').value) || 0;

    const totalAvarias = mortalidadeExcesso + avesMolhadasGranja + avesMolhadasChuva + 
                        quebraMausTratos + avesPapoCheio + outrasQuebras;
    
    const pesoTotal = pesoFrigorifico - totalAvarias;
    document.querySelector('[name="peso_total"]').value = formatNumber(pesoTotal);
    
    calcularValorTotal();
}

// Função para calcular o valor total
function calcularValorTotal() {
    const pesoTotal = parseFloat(document.querySelector('[name="peso_total"]').value) || 0;
    const valorKg = parseFloat(document.querySelector('[name="valor_kg"]').value) || 0;
    
    const valorTotal = pesoTotal * valorKg;
    document.querySelector('[name="valor_total"]').value = formatNumber(valorTotal);
}

// Adicionar listeners para os campos que precisam de cálculos automáticos
document.addEventListener('DOMContentLoaded', function() {
    // Campos relacionados ao frete
    const camposFrete = ['valor_frete', 'pedagios', 'outras_despesas'];
    camposFrete.forEach(campo => {
        const elemento = document.querySelector(`[name="${campo}"]`);
        if (elemento) {
            elemento.addEventListener('input', calcularTotalFrete);
        }
    });

    // Campos relacionados ao peso
    const camposPeso = [
        'peso_frigorifico', 'mortalidade_excesso', 'aves_molhadas_granja',
        'aves_molhadas_chuva', 'quebra_maus_tratos', 'aves_papo_cheio',
        'outras_quebras'
    ];
    camposPeso.forEach(campo => {
        const elemento = document.querySelector(`[name="${campo}"]`);
        if (elemento) {
            elemento.addEventListener('input', calcularPesoTotal);
        }
    });

    // Campo valor por kg
    const campoValorKg = document.querySelector('[name="valor_kg"]');
    if (campoValorKg) {
        campoValorKg.addEventListener('input', calcularValorTotal);
    }
});

// Validação de formulário
(function() {
    'use strict';
    window.addEventListener('load', function() {
        var forms = document.getElementsByClassName('needs-validation');
        Array.prototype.filter.call(forms, function(form) {
            form.addEventListener('submit', function(event) {
                if (form.checkValidity() === false) {
                    event.preventDefault();
                    event.stopPropagation();
                }
                form.classList.add('was-validated');
            }, false);
        });
    }, false);
})();
