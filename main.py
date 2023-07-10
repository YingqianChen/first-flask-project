from website import create_app

app = create_app()

# 运行而非导入时，才执行这段代码
if __name__ == '__main__':
    app.run(debug=True)
