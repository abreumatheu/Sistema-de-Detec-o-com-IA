import streamlit as st
import pandas as pd
from scapy.all import sniff
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
import matplotlib.pyplot as plt
import seaborn as sns
import joblib
import altair as alt
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Função para enviar alerta por e-mail
def send_alert(prediction):
    if prediction == 1:  # Se for identificado tráfego malicioso
        email = "seuemail@example.com"
        senha = "suasenha"
        destinatario = "destinatario@example.com"
        assunto = "Alerta de Intrusão Detectada"
        mensagem = "Uma possível intrusão foi detectada na rede."

        msg = MIMEMultipart()
        msg['From'] = email
        msg['To'] = destinatario
        msg['Subject'] = assunto
        msg.attach(MIMEText(mensagem, 'plain'))

        try:
            servidor = smtplib.SMTP('smtp.gmail.com', 587)
            servidor.starttls()
            servidor.login(email, senha)
            servidor.sendmail(email, destinatario, msg.as_string())
            servidor.close()
            st.write("Alerta enviado com sucesso!")
        except Exception as e:
            st.write(f"Erro ao enviar e-mail: {e}")

# Função para treinar o modelo e fazer previsões
def train_and_predict(X, y):
    # Parâmetros otimizados para RandomForest
    param_grid = {
        'n_estimators': [100, 200, 300],
        'max_depth': [10, 20, 30],
        'min_samples_split': [2, 5, 10]
    }
    
    # Otimização do modelo com GridSearch
    grid_search = GridSearchCV(RandomForestClassifier(random_state=42), param_grid, cv=5)
    grid_search.fit(X, y)

    model = grid_search.best_estimator_

    # Dividir os dados em conjunto de treinamento e teste
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)

    # Treinar o modelo otimizado
    model.fit(X_train, y_train)

    # Fazer previsões
    y_pred = model.predict(X_test)

    # Retornar os dados para visualização
    return y_test, y_pred, model

# Função para visualizar os resultados
def visualize_results(y_test, y_pred):
    st.write("### Relatório de Classificação:")
    report = classification_report(y_test, y_pred, output_dict=True)
    st.table(pd.DataFrame(report).transpose())

    st.write("### Matriz de Confusão:")
    confusion_mat = confusion_matrix(y_test, y_pred)
    fig, ax = plt.subplots()
    sns.heatmap(confusion_mat, annot=True, fmt='d', cmap='Blues', ax=ax)
    ax.set_xlabel('Predito')
    ax.set_ylabel('Verdadeiro')
    st.pyplot(fig)

# Função para gráficos dinâmicos
def show_dynamic_graphs(feature_df):
    st.write("### Gráficos Dinâmicos:")
    chart = alt.Chart(feature_df).mark_bar().encode(
        x='Protocolo:O',
        y='count()',
    )
    st.altair_chart(chart, use_container_width=True)

# Função para extrair características numéricas dos pacotes de rede
def extract_numeric_features(packets):
    features = []
    labels = []  # Neste exemplo, vamos adicionar etiquetas fictícias

    for packet in packets:
        if packet.haslayer('IP'):
            packet_size = len(packet)
            protocol = packet['IP'].proto
            ttl = packet['IP'].ttl

            label = 0 if '192.168.' in packet['IP'].src else 1  # Tráfego da sub-rede 192.168.x.x é normal
            features.append([packet_size, protocol, ttl])
            labels.append(label)

    return features, labels

# Função para captura de pacotes ao vivo com análise em tempo real
def live_packet_capture(model):
    st.write("### Captura e Análise de Pacotes em Tempo Real:")
    def packet_callback(packet):
        if packet.haslayer('IP'):
            packet_size = len(packet)
            protocol = packet['IP'].proto
            ttl = packet['IP'].ttl
            features = [[packet_size, protocol, ttl]]
            prediction = model.predict(features)[0]
            st.write(f"Pacote analisado: Tamanho={packet_size}, Protocolo={protocol}, TTL={ttl}")
            if prediction == 1:
                st.write("Tráfego Malicioso Detectado!")
                send_alert(prediction)

    sniff(prn=packet_callback, store=0)

# Função para carregar e treinar o modelo com um dataset completo
def load_and_train_dataset(dataset):
    st.write("### Carregando e treinando com dataset completo...")
    X = dataset.iloc[:, :-1]
    y = dataset.iloc[:, -1]

    scaler = StandardScaler()
    X = scaler.fit_transform(X)

    y_test, y_pred, model = train_and_predict(X, y)
    visualize_results(y_test, y_pred)
    joblib.dump(model, 'modelo_treinado.pkl')
    st.write("Modelo treinado e salvo como 'modelo_treinado.pkl'.")

# Interface Streamlit
def main():
    st.title("Sistema de Detecção de Intrusões usando IA e Monitoramento de Rede em Tempo Real")

    # Upload e treinamento de dataset
    csv_file = st.file_uploader("Faça o upload de um dataset completo (CSV)", type=["csv"])
    if csv_file is not None:
        dataset = pd.read_csv(csv_file)
        if st.button("Treinar Modelo"):
            load_and_train_dataset(dataset)

    # Captura de pacotes em tempo real com análise
    if st.button("Capturar e Analisar Pacotes em Tempo Real"):
        try:
            model = joblib.load('modelo_treinado.pkl')
            live_packet_capture(model)
        except FileNotFoundError:
            st.write("Por favor, treine o modelo primeiro carregando um dataset.")

if __name__ == '__main__':
    main()
