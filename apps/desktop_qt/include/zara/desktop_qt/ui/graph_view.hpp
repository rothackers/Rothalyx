#pragma once

#include <functional>
#include <vector>

#include <QColor>
#include <QGraphicsView>
#include <QString>

namespace zara::desktop_qt::ui {

struct GraphNode {
    QString id;
    QString label;
    QString detail;
    QColor fill = QColor("#DCE6D8");
    QColor border = QColor("#345E5A");
    QColor label_color = QColor("#0B1F1A");
    QColor detail_color = QColor("#385F5A");
    qreal border_width = 1.4;
    int layer = 0;
    int order = 0;
};

struct GraphEdge {
    QString source;
    QString target;
    QColor color = QColor("#52796F");
    QColor label_color = QColor("#7F5539");
    qreal width = 2.0;
    Qt::PenStyle style = Qt::SolidLine;
    int route_index = 0;
    QString label;
};

class GraphView : public QGraphicsView {
public:
    explicit GraphView(QString placeholder, QWidget* parent = nullptr);

    void show_placeholder(const QString& text = QString());
    void render_graph(const QString& title, const std::vector<GraphNode>& nodes, const std::vector<GraphEdge>& edges);
    void set_node_activated_handler(std::function<void(const QString&)> handler);

protected:
    void keyPressEvent(QKeyEvent* event) override;
    void wheelEvent(QWheelEvent* event) override;
    void mousePressEvent(QMouseEvent* event) override;
    void mouseDoubleClickEvent(QMouseEvent* event) override;

private:
    void apply_zoom(qreal factor);
    void fit_scene_bounds(const QRectF& bounds);
    void nudge_initial_zoom(const QRectF& bounds);

    QString placeholder_;
    QGraphicsScene* scene_ = nullptr;
    std::function<void(const QString&)> node_activated_handler_;
    qreal min_zoom_ = 0.35;
    qreal max_zoom_ = 5.0;
};

}  // namespace zara::desktop_qt::ui
