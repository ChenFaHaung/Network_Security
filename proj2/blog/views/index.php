<?php
require 'config.php';
?>

<html>
<head>
    <title><?php echo $blog_config['title'] ?></title>
    <link rel="stylesheet" href="<?php echo $env_config['root_path'];?>/views/element/element.css">
    <script src="<?php echo $env_config['root_path'];?>/views/element/vue.min.js"></script>
    <script src="<?php echo $env_config['root_path'];?>/views/element/element.js"></script>
</head>
<body>
    <div class="container" id="app">
        <el-menu theme="dark" mode="horizontal">
            <el-menu-item index="1">{{ title }}</el-menu-item>
        </el-menu>
        <el-table :data="tableData" style="width: 100%" @row-click="handleClick">
            <el-table-column prop="id" label="No." width="100"></el-table-column>
            <el-table-column prop="title" label="標題" width="auto"></el-table-column>
        </el-table>
        <el-button type="success" size="large" @click="window.location = '<?php echo $env_config['root_path'];?>/create.php';">New Post</el-button>
    </div>
    <script>
        new Vue({
            el: '#app',
            data() {
                return {
                    title: 'posts',
                    tableData: <?php echo json_encode($data['posts']) ?>
                };
            },
            methods: {
                handleClick(row, event, column) {
                    window.location = `<?php echo $env_config['root_path'];?>/show.php?id=${row.id}`;
                }
            }
        });
    </script>
</body>
</html>
